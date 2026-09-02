package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/config"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// TestUpdateLDAPConfigHandler_DoesNotMutateConfigOnConnectFailure — B_148
// (T_087). updateLDAPConfigHandler used to write the caller's new
// url/bindDN/bindPassword/baseDN/tlsVerify straight onto s.config.LDAP —
// the single shared, in-memory config every other read (GET
// /api/v1/admin/config, an in-flight audit's report labeling) sees
// immediately — BEFORE attempting the LDAP connection at all. A request
// naming an unreachable host or bad credentials still left the server
// pointed at that broken config even though the API call itself reported
// failure: a half-mutated, silently-degraded state, the same family as the
// fail-open paths closed elsewhere tonight. testLDAPHandler already gets
// this right (builds its test client from the request only, never touches
// s.config) — this proves updateLDAPConfigHandler now matches that pattern.
func TestUpdateLDAPConfigHandler_DoesNotMutateConfigOnConnectFailure(t *testing.T) {
	gin.SetMode(gin.TestMode)

	const goodURL = "ldaps://good-dc.corp.local:636"
	const goodBaseDN = "DC=corp,DC=local"

	cfg := config.Default()
	cfg.LDAP.URL = goodURL
	cfg.LDAP.BaseDN = goodBaseDN
	s := &Server{config: cfg, logger: zap.NewNop()}

	// Port 1 on loopback: nothing listens there, so the connection attempt
	// fails immediately (connection refused) rather than timing out — no
	// real network dependency, no flakiness.
	body, err := json.Marshal(LDAPConfigRequest{
		URL:          "ldap://127.0.0.1:1",
		BindDN:       "CN=attacker,DC=evil,DC=example",
		BindPassword: "whatever", // explicit, so resolveAdminBindPassword doesn't need the stored one
		BaseDN:       "DC=evil,DC=example",
	})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}

	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodPut, "/api/v1/admin/config/ldap", bytes.NewReader(body))
	c.Request.Header.Set("Content-Type", "application/json")

	s.updateLDAPConfigHandler(c)

	if rec.Code == http.StatusOK {
		t.Fatalf("expected the connection attempt to fail, got 200: %s", rec.Body.String())
	}

	if s.config.LDAP.URL != goodURL {
		t.Fatalf("s.config.LDAP.URL = %q, want unchanged %q — a failed connection attempt must not mutate the live config", s.config.LDAP.URL, goodURL)
	}
	if s.config.LDAP.BaseDN != goodBaseDN {
		t.Fatalf("s.config.LDAP.BaseDN = %q, want unchanged %q", s.config.LDAP.BaseDN, goodBaseDN)
	}
	if s.config.LDAP.BindDN == "CN=attacker,DC=evil,DC=example" {
		t.Fatal("s.config.LDAP.BindDN was overwritten with the untested request's value")
	}
}

// TestUpdateLDAPConfigHandler_MutatesConfigOnConnectSuccess — non-regression:
// the fix must not break the legitimate case. Cannot dial a real LDAP server
// in this test, so this exercises the earlier failure path
// (ldap.NewClient's own validation, e.g. an unparseable URL) to confirm the
// handler still reports an error and doesn't silently accept malformed
// input — a full success-path integration lives beyond unit-test reach
// without a real directory, but this at minimum locks that a construction
// error is reported cleanly rather than swallowed.
func TestUpdateLDAPConfigHandler_RejectsInvalidURLCleanly(t *testing.T) {
	gin.SetMode(gin.TestMode)

	s := &Server{config: config.Default(), logger: zap.NewNop()}

	body, err := json.Marshal(LDAPConfigRequest{
		URL:          "not-a-valid-ldap-url",
		BindPassword: "whatever",
		BaseDN:       "DC=example,DC=com",
	})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}

	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodPut, "/api/v1/admin/config/ldap", bytes.NewReader(body))
	c.Request.Header.Set("Content-Type", "application/json")

	s.updateLDAPConfigHandler(c)

	if rec.Code == http.StatusOK {
		t.Fatalf("expected an error for an invalid URL, got 200: %s", rec.Body.String())
	}
	if s.config.LDAP.URL == "not-a-valid-ldap-url" {
		t.Fatal("s.config.LDAP.URL was set to the invalid value before validation even completed")
	}
}
