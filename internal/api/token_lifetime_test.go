package api

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/etcsec-com/etc-collector/internal/config"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// issueToken drives the real createTokenHandler and returns the lifetime it granted,
// derived from the expiresAt it reports back to the caller. Going through the handler
// (rather than re-deriving the resolution in the test) is the point: the defect was
// precisely that the handler ignored the configured value.
func issueToken(t *testing.T, configured time.Duration, requested string) time.Duration {
	t.Helper()
	gin.SetMode(gin.TestMode)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	cfg := config.Default()
	cfg.Auth.TokenLifetime = configured
	cfg.Auth.PrivateKey = key

	s := &Server{config: cfg, logger: zap.NewNop()}

	body, err := json.Marshal(TokenRequest{Service: "test", Duration: requested})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodPost, "/tokens", bytes.NewReader(body))
	c.Request.Header.Set("Content-Type", "application/json")

	issuedAt := time.Now()
	s.createTokenHandler(c)

	if rec.Code != http.StatusOK {
		t.Fatalf("createTokenHandler returned %d: %s", rec.Code, rec.Body.String())
	}

	var resp struct {
		Token     string `json:"token"`
		ExpiresAt string `json:"expiresAt"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Token == "" {
		t.Fatal("no token issued")
	}

	expiresAt, err := time.Parse(time.RFC3339, resp.ExpiresAt)
	if err != nil {
		t.Fatalf("parse expiresAt %q: %v", resp.ExpiresAt, err)
	}
	return expiresAt.Sub(issuedAt).Round(time.Minute)
}

// TestTokenLifetime_ConfigIsActuallyApplied — B_037 (T_038). auth.tokenLifetime was
// parsed from config.yaml, defaulted to 30 days, written into the generated Windows
// config as `tokenLifetime: 720h`, and echoed back to the client by /admin/config —
// while token issuance used a hardcoded 24h. The customer held written confirmation,
// from our own API, of a value the product did not apply.
func TestTokenLifetime_ConfigIsActuallyApplied(t *testing.T) {
	const configured = 720 * time.Hour // what a customer writes and what the API confirms

	t.Run("the configured lifetime reaches the issued token", func(t *testing.T) {
		got := issueToken(t, configured, "")
		if got != configured {
			t.Fatalf("issued token lasts %v, want %v — the value the API reports to the customer", got, configured)
		}
		if got == defaultTokenLifetime {
			t.Fatal("still issuing the hardcoded 24h regardless of auth.tokenLifetime")
		}
	})

	t.Run("the shipped default of 30 days now applies", func(t *testing.T) {
		// config.Default() always advertised 30 days; it simply never reached issuance.
		// This is the behaviour change announced in the CHANGELOG.
		if got := issueToken(t, config.Default().Auth.TokenLifetime, ""); got != 30*24*time.Hour {
			t.Fatalf("issued token lasts %v, want 720h", got)
		}
	})

	t.Run("an unset lifetime keeps the historical 24h", func(t *testing.T) {
		// A deployment whose file has no auth: section must see no change at all.
		if got := issueToken(t, 0, ""); got != defaultTokenLifetime {
			t.Fatalf("issued token lasts %v, want the historical %v", got, defaultTokenLifetime)
		}
	})

	t.Run("an explicit per-request duration still wins", func(t *testing.T) {
		// The request is the most specific source, like a CLI flag elsewhere.
		if got := issueToken(t, configured, "1h"); got != time.Hour {
			t.Fatalf("issued token lasts %v, want the requested 1h", got)
		}
	})

	t.Run("an invalid requested duration is still rejected", func(t *testing.T) {
		gin.SetMode(gin.TestMode)
		cfg := config.Default()
		s := &Server{config: cfg, logger: zap.NewNop()}

		body, _ := json.Marshal(TokenRequest{Service: "test", Duration: "not-a-duration"})
		rec := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(rec)
		c.Request = httptest.NewRequest(http.MethodPost, "/tokens", bytes.NewReader(body))
		c.Request.Header.Set("Content-Type", "application/json")

		s.createTokenHandler(c)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("got %d, want 400 for a malformed duration", rec.Code)
		}
	})
}
