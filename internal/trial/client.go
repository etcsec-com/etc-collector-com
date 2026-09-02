package trial

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Client is the HTTP client for the trial-service.
//
// It refuses fleet endpoints and non-trial tokens as a defense-in-depth
// measure so that a trial token can never accidentally be sent to prod API.
type Client struct {
	baseURL  string
	apiToken string
	http     *http.Client
}

// NewClient validates the base URL and builds a client. apiToken may be empty
// at this point; it is set later after successful enroll.
func NewClient(baseURL string) (*Client, error) {
	if baseURL == "" {
		return nil, errors.New("trial: base URL is required")
	}
	lower := strings.ToLower(baseURL)
	if strings.Contains(lower, "/api/fleet") || strings.Contains(lower, "/api/v1/") {
		return nil, fmt.Errorf("trial: refusing fleet-style URL %q (trial uses /v1/trial)", baseURL)
	}
	if !strings.Contains(lower, "/v1/trial") {
		return nil, fmt.Errorf("trial: base URL must contain /v1/trial, got %q", baseURL)
	}
	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		http:    &http.Client{Timeout: 120 * time.Second},
	}, nil
}

// SetAPIToken stores the token returned by Enroll.
func (c *Client) SetAPIToken(token string) error {
	if !strings.HasPrefix(token, APITokenPrefix) {
		return fmt.Errorf("trial: API token must start with %q", APITokenPrefix)
	}
	c.apiToken = token
	return nil
}

// Enroll exchanges a tcol_ enrollment token for a tapi_ API token.
func (c *Client) Enroll(ctx context.Context, req EnrollRequest) (*EnrollResponse, error) {
	if !strings.HasPrefix(req.EnrollmentToken, EnrollTokenPrefix) {
		return nil, fmt.Errorf("trial: enrollment token must start with %q", EnrollTokenPrefix)
	}
	resp, err := c.do(ctx, http.MethodPost, "/enroll", req, false)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("trial enroll: HTTP %d: %s", resp.StatusCode, readBody(resp))
	}
	var out EnrollResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("trial enroll: decode: %w", err)
	}
	if out.APIToken == "" || out.CollectorID == "" {
		return nil, errors.New("trial enroll: missing collectorId or apiToken in response")
	}
	if !strings.HasPrefix(out.APIToken, APITokenPrefix) {
		return nil, fmt.Errorf("trial enroll: returned API token lacks %q prefix", APITokenPrefix)
	}
	return &out, nil
}

// PollResult captures the server's response to /commands.
type PollResult struct {
	// Idle is true when the server returned 204 (nothing to do).
	Idle bool
	// Completed is true when the server signals the session is closed
	// (404 or Status="completed" in body).
	Completed bool
	// Command is non-nil when a command was dispatched.
	Command *Command
}

// PollCommands fetches the next command. Returns (PollResult, nil) on success.
func (c *Client) PollCommands(ctx context.Context) (*PollResult, error) {
	resp, err := c.do(ctx, http.MethodGet, "/commands", nil, true)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusNoContent:
		return &PollResult{Idle: true}, nil
	case http.StatusNotFound:
		return &PollResult{Completed: true}, nil
	case http.StatusOK:
		// Parse body; handle both shapes (single command or wrapper).
		if resp.Header.Get("X-Trial-Status") == "completed" {
			return &PollResult{Completed: true}, nil
		}
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("trial poll: read body: %w", err)
		}
		if len(bytes.TrimSpace(body)) == 0 {
			return &PollResult{Idle: true}, nil
		}
		var parsed CommandsResponse
		if err := json.Unmarshal(body, &parsed); err != nil {
			return nil, fmt.Errorf("trial poll: decode: %w", err)
		}
		if parsed.Status == "completed" {
			return &PollResult{Completed: true}, nil
		}
		if len(parsed.Commands) > 0 {
			cmd := parsed.Commands[0]
			return &PollResult{Command: &cmd}, nil
		}
		if parsed.ID != "" && parsed.Type != "" {
			return &PollResult{Command: &Command{ID: parsed.ID, Type: parsed.Type, Params: parsed.Params}}, nil
		}
		return &PollResult{Idle: true}, nil
	case http.StatusUnauthorized:
		return nil, fmt.Errorf("trial poll: unauthorized (token rejected)")
	default:
		return nil, fmt.Errorf("trial poll: HTTP %d: %s", resp.StatusCode, readBody(resp))
	}
}

// SubmitResult POSTs a command result to the trial-service.
func (c *Client) SubmitResult(ctx context.Context, commandID string, result CommandResult) error {
	path := "/commands/" + commandID + "/result"
	resp, err := c.do(ctx, http.MethodPost, path, result, true)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("trial result: HTTP %d: %s", resp.StatusCode, readBody(resp))
	}
	return nil
}

func (c *Client) do(ctx context.Context, method, path string, body interface{}, auth bool) (*http.Response, error) {
	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("trial: marshal: %w", err)
		}
		reader = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reader)
	if err != nil {
		return nil, fmt.Errorf("trial: request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "etc-collector-trial")
	if auth {
		if c.apiToken == "" {
			return nil, errors.New("trial: API token not set")
		}
		req.Header.Set("Authorization", "Bearer "+c.apiToken)
	}
	return c.http.Do(req)
}

func readBody(resp *http.Response) string {
	b, _ := io.ReadAll(resp.Body)
	if len(b) > 512 {
		b = b[:512]
	}
	return string(b)
}
