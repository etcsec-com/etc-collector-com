package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/config"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// TestResolveAdminBindPassword — T_041/B_040. A bind password already held by this
// server must never be usable against an endpoint the caller names in the request
// unless the caller also supplies the password. Same guarantee resolveLDAPConfig
// (T_025) gives the cloud-command path, now proven for the local admin API path that
// security proved live: the real DC01 credential reaching a listener the caller named,
// in the clear, via a request naming only a new URL.
func TestResolveAdminBindPassword(t *testing.T) {
	const storedSecret = "T041-REAL-DC01-SECRET-9f3a"
	const storedURL = "ldaps://dc01.corp.local:636"

	newServerWithStoredCreds := func() *Server {
		cfg := config.Default()
		cfg.LDAP.URL = storedURL
		cfg.LDAP.BindPassword = storedSecret
		return &Server{config: cfg, logger: zap.NewNop()}
	}

	t.Run("stored password refused against a different caller-supplied URL", func(t *testing.T) {
		s := newServerWithStoredCreds()
		password, err := s.resolveAdminBindPassword("ldaps://attacker.example:636", "")
		if err == nil {
			t.Fatal("a stored bind password must NOT be usable against a different caller-supplied URL")
		}
		if password == storedSecret {
			t.Fatal("the refused call still returned the stored secret")
		}
		if strings.Contains(err.Error(), storedSecret) {
			t.Fatal("the error message leaks the stored secret")
		}
	})

	t.Run("stored password reused when the URL matches what it was configured for", func(t *testing.T) {
		s := newServerWithStoredCreds()
		password, err := s.resolveAdminBindPassword(storedURL, "")
		if err != nil {
			t.Fatalf("re-testing/re-saving the same endpoint must keep working: %v", err)
		}
		if password != storedSecret {
			t.Fatalf("expected the stored password to be reused, got %q", password)
		}
	})

	t.Run("an explicit password in the request always wins, whatever the URL", func(t *testing.T) {
		s := newServerWithStoredCreds()
		password, err := s.resolveAdminBindPassword("ldaps://new-dc.corp.local:636", "operator-supplied-password")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if password != "operator-supplied-password" {
			t.Fatalf("expected the caller-supplied password, got %q", password)
		}
	})

	t.Run("no stored secret means nothing to leak — empty password allowed on a fresh config", func(t *testing.T) {
		s := &Server{config: config.Default(), logger: zap.NewNop()}
		password, err := s.resolveAdminBindPassword("ldaps://new-dc.corp.local:636", "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if password != "" {
			t.Fatalf("expected empty password, got %q", password)
		}
	})
}

// TestUpdateLDAPConfigHandler_RefusesPasswordReuseAgainstNewURL — HTTP-level proof that
// PUT /api/v1/admin/config/ldap refuses before ever attempting a network bind when the
// request names a different URL and omits the password. This is the literal exploited
// route (config update reuses the stored password to connect to the caller's URL).
func TestUpdateLDAPConfigHandler_RefusesPasswordReuseAgainstNewURL(t *testing.T) {
	gin.SetMode(gin.TestMode)
	const storedSecret = "T041-REAL-DC01-SECRET-9f3a"

	cfg := config.Default()
	cfg.LDAP.URL = "ldaps://dc01.corp.local:636"
	cfg.LDAP.BindPassword = storedSecret
	s := &Server{config: cfg, logger: zap.NewNop()}

	body, err := json.Marshal(LDAPConfigRequest{
		URL:    "ldaps://attacker.example:636",
		BaseDN: "DC=corp,DC=local",
	})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}

	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodPut, "/api/v1/admin/config/ldap", bytes.NewReader(body))
	c.Request.Header.Set("Content-Type", "application/json")

	s.updateLDAPConfigHandler(c)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("got %d, want 400 refusing to reuse the stored password: %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), storedSecret) {
		t.Fatal("the stored secret leaked into the HTTP response")
	}
}

// TestTestLDAPHandler_RefusesPasswordReuseAgainstNewURL — same proof for
// POST /api/v1/admin/config/ldap/test, the exact code cited in the live D6 audit
// (admin.go:195-197 pre-fix) and the route security exercised in T_040.
func TestTestLDAPHandler_RefusesPasswordReuseAgainstNewURL(t *testing.T) {
	gin.SetMode(gin.TestMode)
	const storedSecret = "T041-REAL-DC01-SECRET-9f3a"

	cfg := config.Default()
	cfg.LDAP.URL = "ldaps://dc01.corp.local:636"
	cfg.LDAP.BindPassword = storedSecret
	s := &Server{config: cfg, logger: zap.NewNop()}

	body, err := json.Marshal(LDAPConfigRequest{
		URL:    "ldaps://attacker.example:636",
		BaseDN: "DC=corp,DC=local",
	})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}

	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodPost, "/api/v1/admin/config/ldap/test", bytes.NewReader(body))
	c.Request.Header.Set("Content-Type", "application/json")

	s.testLDAPHandler(c)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("got %d, want 400 refusing to reuse the stored password: %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), storedSecret) {
		t.Fatal("the stored secret leaked into the HTTP response")
	}
}
