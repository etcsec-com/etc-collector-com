package saas

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// largeResult builds a CommandResult with a payload big enough to exercise
// the gzip path (compressible JSON). 200 KB raw — enough that the test
// asserts a measurable compression ratio without slowing the suite.
func largeResult() CommandResult {
	rows := make([]map[string]string, 1000)
	for i := range rows {
		rows[i] = map[string]string{
			"id":          "00000000-0000-0000-0000-000000000000",
			"displayName": "user with a moderately long display name to compress",
			"upn":         "user.with.long.upn@contoso.onmicrosoft.com",
			"createdAt":   "2026-05-03T20:30:00Z",
		}
	}
	return CommandResult{
		CommandID:   "test-cmd",
		Status:      "success",
		StartedAt:   "2026-05-03T20:30:00Z",
		CompletedAt: "2026-05-03T20:31:00Z",
		Result:      map[string]any{"rows": rows},
	}
}

func TestSubmitResult_GzipsByDefault(t *testing.T) {
	t.Setenv("ETC_COLLECTOR_SUBMIT_GZIP", "")

	var gotEncoding string
	var gotPayloadSize int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotEncoding = r.Header.Get("Content-Encoding")
		var body io.Reader = r.Body
		if gotEncoding == "gzip" {
			gz, err := gzip.NewReader(r.Body)
			if err != nil {
				http.Error(w, err.Error(), 400)
				return
			}
			defer gz.Close()
			body = gz
		}
		decoded, _ := io.ReadAll(body)
		gotPayloadSize = len(decoded)
		// Verify it parses as JSON
		var sink map[string]any
		if err := json.Unmarshal(decoded, &sink); err != nil {
			t.Errorf("server received non-JSON body after decompress: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "test-key")
	if err := c.SubmitResult(context.Background(), "collector-1", largeResult()); err != nil {
		t.Fatalf("SubmitResult: %v", err)
	}
	if gotEncoding != "gzip" {
		t.Errorf("Content-Encoding = %q, want gzip", gotEncoding)
	}
	if gotPayloadSize == 0 {
		t.Errorf("server received empty body")
	}
}

func TestSubmitResult_RespectsGzipDisableEnv(t *testing.T) {
	t.Setenv("ETC_COLLECTOR_SUBMIT_GZIP", "false")

	var gotEncoding string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotEncoding = r.Header.Get("Content-Encoding")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "test-key")
	if err := c.SubmitResult(context.Background(), "collector-1", largeResult()); err != nil {
		t.Fatalf("SubmitResult: %v", err)
	}
	if gotEncoding == "gzip" {
		t.Errorf("Content-Encoding = gzip, expected empty (gzip disabled)")
	}
}

func TestSubmitResult_FallsBackOnUnsupportedMediaType(t *testing.T) {
	t.Setenv("ETC_COLLECTOR_SUBMIT_GZIP", "")

	var attempts []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts = append(attempts, r.Header.Get("Content-Encoding"))
		if r.Header.Get("Content-Encoding") == "gzip" {
			w.WriteHeader(http.StatusUnsupportedMediaType)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "test-key")
	if err := c.SubmitResult(context.Background(), "collector-1", largeResult()); err != nil {
		t.Fatalf("SubmitResult after fallback: %v", err)
	}
	if len(attempts) != 2 {
		t.Fatalf("expected 2 attempts (gzip then plain), got %d: %v", len(attempts), attempts)
	}
	if attempts[0] != "gzip" {
		t.Errorf("first attempt encoding = %q, want gzip", attempts[0])
	}
	if attempts[1] != "" {
		t.Errorf("fallback attempt encoding = %q, want empty", attempts[1])
	}
}

func TestPostResult_CompressionRatio(t *testing.T) {
	c := NewClient("http://unused", "test-key")
	// Use a never-dialed server URL so we exercise marshal+compress and bail
	// before the network call. We only need the sizes back, not the HTTP roundtrip.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	c.baseURL = srv.URL

	resp, payloadSize, submitSize, usedGzip, err := c.postResult(context.Background(), "/api/fleet/collectors/x/results", largeResult(), true)
	if err != nil {
		t.Fatalf("postResult: %v", err)
	}
	resp.Body.Close()

	if !usedGzip {
		t.Fatal("usedGzip = false")
	}
	if submitSize >= payloadSize {
		t.Errorf("compression ineffective: submitSize=%d payloadSize=%d", submitSize, payloadSize)
	}
	ratio := float64(payloadSize) / float64(submitSize)
	if ratio < 5.0 {
		t.Errorf("expected highly repetitive JSON to compress >5x, got %.2fx (raw=%d gzip=%d)", ratio, payloadSize, submitSize)
	}
	t.Logf("compression ratio %.1fx (raw=%d gzip=%d)", ratio, payloadSize, submitSize)
}
