// Package saas implements the SaaS API client for cloud integration
package saas

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/etcsec-com/etc-collector/internal/logger"
)

// Client is the SaaS API client
type Client struct {
	baseURL    string
	apiKey     string
	httpClient *http.Client
	logger     *logger.Logger
}

// ClientOption is a functional option for Client
type ClientOption func(*Client)

// WithHTTPClient sets a custom HTTP client
func WithHTTPClient(client *http.Client) ClientOption {
	return func(c *Client) {
		c.httpClient = client
	}
}

// WithLogger sets a custom logger
func WithLogger(l *logger.Logger) ClientOption {
	return func(c *Client) {
		c.logger = l
	}
}

// NewClient creates a new SaaS API client
func NewClient(baseURL, apiKey string, opts ...ClientOption) *Client {
	c := &Client{
		baseURL: baseURL,
		apiKey:  apiKey,
		httpClient: &http.Client{
			Timeout: 60 * time.Second,
		},
		logger: logger.Global(),
	}

	for _, opt := range opts {
		opt(c)
	}

	return c
}

// SetApiKey updates the API key
func (c *Client) SetApiKey(apiKey string) {
	c.apiKey = apiKey
}

// doRequest performs an HTTP request with Bearer authentication
func (c *Client) doRequest(ctx context.Context, method, path string, body interface{}) (*http.Response, error) {
	var reqBody io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("marshal request body: %w", err)
		}
		reqBody = bytes.NewReader(data)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reqBody)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}

	return c.httpClient.Do(req)
}

// readErrorBody reads and formats an error response body
func readErrorBody(resp *http.Response) string {
	body, _ := io.ReadAll(resp.Body)
	if len(body) > 0 {
		return string(body)
	}
	return resp.Status
}

// Enroll registers this collector with the SaaS platform
func (c *Client) Enroll(ctx context.Context, req EnrollRequest) (*EnrollResponse, error) {
	// Defense in depth: refuse trial-issued tokens so a tcol_/tapi_ can never
	// accidentally reach the fleet API. The trial flow uses its own client.
	if strings.HasPrefix(req.EnrollmentToken, "tcol_") || strings.HasPrefix(req.EnrollmentToken, "tapi_") {
		return nil, fmt.Errorf("fleet client refuses trial tokens (use 'etc-collector trial' instead)")
	}
	resp, err := c.doRequest(ctx, http.MethodPost, "/api/fleet/enroll", req)
	if err != nil {
		return nil, fmt.Errorf("enrollment request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("enrollment failed with status %d: %s", resp.StatusCode, readErrorBody(resp))
	}

	var enrollResp EnrollResponse
	if err := json.NewDecoder(resp.Body).Decode(&enrollResp); err != nil {
		return nil, fmt.Errorf("decode enrollment response: %w", err)
	}

	// Store the API key for subsequent requests
	c.apiKey = enrollResp.ApiKey

	return &enrollResp, nil
}

// PollCommands fetches pending commands from the SaaS backend
func (c *Client) PollCommands(ctx context.Context, collectorID string) (*CommandsResponse, error) {
	path := fmt.Sprintf("/api/fleet/collectors/%s/commands", collectorID)

	resp, err := c.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, fmt.Errorf("poll commands failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("poll commands returned status %d: %s", resp.StatusCode, readErrorBody(resp))
	}

	var cmdResp CommandsResponse
	if err := json.NewDecoder(resp.Body).Decode(&cmdResp); err != nil {
		return nil, fmt.Errorf("decode commands response: %w", err)
	}

	return &cmdResp, nil
}

// SubmitResult sends a command execution result to the SaaS backend.
//
// v3.1.34 — Audit results are gzip-encoded by default before POST. Cloudflare
// fronts api.etcsec.com and caps request bodies at 100 MB on Free/Pro plans
// (200 MB on Business). Raw audit payloads on the pilot tenant reach 309-317 MB
// (sign-in events have a very repetitive structure → ~10x compression ratio),
// so without gzip every Azure SaaS-managed audit submit dies with HTTP 413
// from Cloudflare BEFORE reaching the backend. With gzip a 317 MB raw payload
// drops to ~30 MB, comfortably under the 100 MB cap.
//
// Set ETC_COLLECTOR_SUBMIT_GZIP=false to disable (escape hatch if a backend
// without the gzip-decompress middleware needs to accept submissions).
//
// On HTTP 415 (Unsupported Media Type) we retry once without gzip — covers
// the transition window where collectors and backend get deployed in either
// order and the backend hasn't been taught to gunzip yet.
func (c *Client) SubmitResult(ctx context.Context, collectorID string, result CommandResult) error {
	path := fmt.Sprintf("/api/fleet/collectors/%s/results", collectorID)

	gzipEnabled := os.Getenv("ETC_COLLECTOR_SUBMIT_GZIP") != "false"

	resp, payloadSize, submitSize, usedGzip, err := c.postResult(ctx, path, result, gzipEnabled)
	if err != nil {
		return fmt.Errorf("submit result failed: %w", err)
	}
	// Auto-fallback: backend doesn't grok our gzip → retry plain once.
	if usedGzip && resp.StatusCode == http.StatusUnsupportedMediaType {
		resp.Body.Close()
		c.logger.Warn("SaaS rejected gzip submit (415) — retrying without compression",
			"collectorId", collectorID, "submitSizeBytes", submitSize)
		resp, payloadSize, submitSize, usedGzip, err = c.postResult(ctx, path, result, false)
		if err != nil {
			return fmt.Errorf("submit result (gzip fallback) failed: %w", err)
		}
	}
	defer resp.Body.Close()

	encoding := "identity"
	ratio := 1.0
	if usedGzip {
		encoding = "gzip"
		if submitSize > 0 {
			ratio = float64(payloadSize) / float64(submitSize)
		}
	}
	c.logger.Info("Submit result wire payload",
		"collectorId", collectorID,
		"payloadSizeBytes", payloadSize,
		"submitSizeBytes", submitSize,
		"contentEncoding", encoding,
		"compressionRatio", fmt.Sprintf("%.1fx", ratio),
		"status", resp.StatusCode,
	)

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("submit result returned status %d: %s", resp.StatusCode, readErrorBody(resp))
	}

	return nil
}

// postResult marshals + optionally gzips + POSTs the audit result. Returns
// the response, the raw JSON size, the on-the-wire size, whether gzip was
// applied, and any transport error. The caller is responsible for closing
// resp.Body.
func (c *Client) postResult(ctx context.Context, path string, result CommandResult, useGzip bool) (*http.Response, int, int, bool, error) {
	data, err := json.Marshal(result)
	if err != nil {
		return nil, 0, 0, false, fmt.Errorf("marshal result: %w", err)
	}
	payloadSize := len(data)

	var body io.Reader
	var submitSize int
	if useGzip {
		var buf bytes.Buffer
		gz := gzip.NewWriter(&buf)
		if _, err := gz.Write(data); err != nil {
			return nil, payloadSize, 0, false, fmt.Errorf("gzip write: %w", err)
		}
		if err := gz.Close(); err != nil {
			return nil, payloadSize, 0, false, fmt.Errorf("gzip close: %w", err)
		}
		submitSize = buf.Len()
		body = &buf
	} else {
		submitSize = payloadSize
		body = bytes.NewReader(data)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, body)
	if err != nil {
		return nil, payloadSize, submitSize, useGzip, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if useGzip {
		req.Header.Set("Content-Encoding", "gzip")
	}
	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, payloadSize, submitSize, useGzip, err
	}
	return resp, payloadSize, submitSize, useGzip, nil
}

// SendHealth sends a health report to the SaaS backend and returns the response body.
//
// K3 (T_045): the response can additively carry commandSigningPublicKeys — this is how
// an already-enrolled collector receives (or rotates) its command-signing key set
// through a channel it already polls, without re-enrolling. A decode failure is
// tolerated rather than surfaced as an error: this field is additive and a backend that
// hasn't shipped it yet may return an empty or non-JSON 200 body, which must not break
// health reporting.
func (c *Client) SendHealth(ctx context.Context, collectorID string, health HealthReport) (*HealthResponse, error) {
	path := fmt.Sprintf("/api/fleet/collectors/%s/health", collectorID)

	resp, err := c.doRequest(ctx, http.MethodPost, path, health)
	if err != nil {
		return nil, fmt.Errorf("send health failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("send health returned status %d: %s", resp.StatusCode, readErrorBody(resp))
	}

	var healthResp HealthResponse
	if err := json.NewDecoder(resp.Body).Decode(&healthResp); err != nil {
		return &HealthResponse{}, nil
	}
	return &healthResp, nil
}

// Unenroll notifies the SaaS backend that this collector is being removed
func (c *Client) Unenroll(ctx context.Context, collectorID string) error {
	path := fmt.Sprintf("/api/fleet/collectors/%s/unenroll", collectorID)

	resp, err := c.doRequest(ctx, http.MethodPost, path, nil)
	if err != nil {
		return fmt.Errorf("unenroll request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unenroll returned status %d: %s", resp.StatusCode, readErrorBody(resp))
	}

	return nil
}
