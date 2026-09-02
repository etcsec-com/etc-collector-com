package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/config"
	"github.com/etcsec-com/etc-collector/internal/guitoken"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// TestGuiTokenMiddleware_FailClosedWithoutHash — T_041/B_040. A missing gui-token hash
// used to be treated as "dev/legacy mode" and let every /admin (and /auth/token)
// request through unauthenticated — exactly the default state of any collector
// upgraded, rather than reinstalled, before gui-token existed. The admin API must
// refuse, not authorize, when no hash is configured.
func TestGuiTokenMiddleware_FailClosedWithoutHash(t *testing.T) {
	gin.SetMode(gin.TestMode)

	s := &Server{config: config.Default(), logger: zap.NewNop()}

	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodGet, "/api/v1/admin/config", nil)

	s.guiTokenMiddleware()(c)

	if !c.IsAborted() {
		t.Fatal("middleware must abort the request chain when no gui-token hash is configured")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("got %d, want 401 when no gui-token hash is configured — fail-closed, not open", rec.Code)
	}
}

// TestGuiTokenMiddleware_ValidTokenStillWorks — the fail-closed change must not break
// the normal case: a correctly configured hash and a matching token still authorize.
func TestGuiTokenMiddleware_ValidTokenStillWorks(t *testing.T) {
	gin.SetMode(gin.TestMode)

	token, err := guitoken.Generate()
	if err != nil {
		t.Fatalf("generate token: %v", err)
	}

	s := &Server{config: config.Default(), logger: zap.NewNop(), guiTokenHash: guitoken.Hash(token)}

	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodGet, "/api/v1/admin/config", nil)
	c.Request.Header.Set("X-GUI-Token", token)

	s.guiTokenMiddleware()(c)

	if c.IsAborted() {
		t.Fatalf("a valid token must not be rejected: %s", rec.Body.String())
	}
}

// TestGuiTokenMiddleware_WrongTokenStillRejected — a configured-but-wrong token must
// keep failing exactly as before; only the "no hash at all" case changed.
func TestGuiTokenMiddleware_WrongTokenStillRejected(t *testing.T) {
	gin.SetMode(gin.TestMode)

	token, err := guitoken.Generate()
	if err != nil {
		t.Fatalf("generate token: %v", err)
	}

	s := &Server{config: config.Default(), logger: zap.NewNop(), guiTokenHash: guitoken.Hash(token)}

	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodGet, "/api/v1/admin/config", nil)
	c.Request.Header.Set("X-GUI-Token", "wrong-token")

	s.guiTokenMiddleware()(c)

	if !c.IsAborted() || rec.Code != http.StatusUnauthorized {
		t.Fatalf("got aborted=%v code=%d, want 401 for a wrong token", c.IsAborted(), rec.Code)
	}
}

// TestGuiTokenMiddleware_QueryStringTokenNoLongerAccepted — B_091 (T_077). A
// ?gui_token= query-string fallback used to work here — query strings land in
// access logs on this server, any reverse proxy in front of it, browser
// history, and outbound Referer headers, none of which a leaked secret can be
// recalled from. Verified before removing it: nothing in this repo (including
// the embedded GUI's own frontend JS) ever constructed a gui_token= URL, only
// this middleware read it — so removing it breaks no internal caller.
func TestGuiTokenMiddleware_QueryStringTokenNoLongerAccepted(t *testing.T) {
	gin.SetMode(gin.TestMode)

	token, err := guitoken.Generate()
	if err != nil {
		t.Fatalf("generate token: %v", err)
	}

	s := &Server{config: config.Default(), logger: zap.NewNop(), guiTokenHash: guitoken.Hash(token)}

	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodGet, "/api/v1/admin/config?gui_token="+token, nil)
	// Deliberately no X-GUI-Token header — the real token is present only in
	// the query string, exactly the case this fix closes.

	s.guiTokenMiddleware()(c)

	if !c.IsAborted() || rec.Code != http.StatusUnauthorized {
		t.Fatalf("got aborted=%v code=%d, want 401 — a token in the query string alone must no longer authenticate", c.IsAborted(), rec.Code)
	}
}

// postVerifyGuiToken drives the real verifyGuiTokenHandler with a JSON body
// {"token": token} and returns the decoded response plus the HTTP status.
func postVerifyGuiToken(t *testing.T, s *Server, token string) (map[string]interface{}, int) {
	t.Helper()
	gin.SetMode(gin.TestMode)

	body, err := json.Marshal(map[string]string{"token": token})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}

	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodPost, "/api/v1/auth/gui-token/verify", bytes.NewReader(body))
	c.Request.Header.Set("Content-Type", "application/json")

	s.verifyGuiTokenHandler(c)

	var resp map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response %s: %v", rec.Body.String(), err)
	}
	return resp, rec.Code
}

// TestVerifyGuiTokenHandler_DaemonModeWrongTokenRejected — B_134 (T_060), the exact
// scenario the backlog verified live: a Server shaped like daemon mode (guiTokenDir
// set — hash reloaded from disk on every request via SetGuiTokenDir/StartEmbeddedGUI
// — guiTokenHash left at its zero value, since daemon mode never calls
// SetGuiTokenHash). Before this fix, verifyGuiTokenHandler read the static
// guiTokenHash field directly, which is always "" in this exact configuration, so it
// reported {"valid":true,"required":false} — "no auth needed" — for a WRONG token,
// even though guiTokenMiddleware (using currentGuiTokenHash(), which DOES check the
// disk-backed hash) would reject the very same request.
func TestVerifyGuiTokenHandler_DaemonModeWrongTokenRejected(t *testing.T) {
	dir := t.TempDir()
	token, err := guitoken.Generate()
	if err != nil {
		t.Fatalf("generate token: %v", err)
	}
	if err := guitoken.SaveHash(dir, guitoken.Hash(token)); err != nil {
		t.Fatalf("save hash: %v", err)
	}

	// guiTokenHash intentionally left unset — this is what StartEmbeddedGUI actually
	// produces (SetGuiTokenDir only, never SetGuiTokenHash).
	s := &Server{config: config.Default(), logger: zap.NewNop(), guiTokenDir: dir}

	resp, code := postVerifyGuiToken(t, s, "wrong-token")

	if code != http.StatusOK {
		t.Fatalf("got status %d, want 200", code)
	}
	if valid, _ := resp["valid"].(bool); valid {
		t.Fatalf("got %+v, want valid:false for a wrong token against a real disk-backed hash", resp)
	}
	if _, hasRequired := resp["required"]; hasRequired {
		t.Fatalf("got %+v — a configured-and-wrong case must not carry the same shape as the no-hash-configured case", resp)
	}
}

// TestVerifyGuiTokenHandler_DaemonModeCorrectTokenAccepted — non-regression: the same
// daemon-mode Server shape, with the RIGHT token, must still say valid:true. The fix
// must close the oracle without breaking the legitimate case.
func TestVerifyGuiTokenHandler_DaemonModeCorrectTokenAccepted(t *testing.T) {
	dir := t.TempDir()
	token, err := guitoken.Generate()
	if err != nil {
		t.Fatalf("generate token: %v", err)
	}
	if err := guitoken.SaveHash(dir, guitoken.Hash(token)); err != nil {
		t.Fatalf("save hash: %v", err)
	}

	s := &Server{config: config.Default(), logger: zap.NewNop(), guiTokenDir: dir}

	resp, code := postVerifyGuiToken(t, s, token)

	if code != http.StatusOK {
		t.Fatalf("got status %d, want 200", code)
	}
	if valid, _ := resp["valid"].(bool); !valid {
		t.Fatalf("got %+v, want valid:true for the real token", resp)
	}
}

// TestVerifyGuiTokenHandler_MalformedAndWrongTokenIndistinguishable — B_134: an
// unauthenticated caller must not be able to tell "I sent no/malformed token" apart
// from "I sent a wrong token" via response shape or status code. Before this fix the
// former was 400 invalid_request and the latter was 200 valid:false.
func TestVerifyGuiTokenHandler_MalformedAndWrongTokenIndistinguishable(t *testing.T) {
	dir := t.TempDir()
	token, err := guitoken.Generate()
	if err != nil {
		t.Fatalf("generate token: %v", err)
	}
	if err := guitoken.SaveHash(dir, guitoken.Hash(token)); err != nil {
		t.Fatalf("save hash: %v", err)
	}
	s := &Server{config: config.Default(), logger: zap.NewNop(), guiTokenDir: dir}

	emptyResp, emptyCode := postVerifyGuiToken(t, s, "")
	wrongResp, wrongCode := postVerifyGuiToken(t, s, "a-plausible-but-wrong-token")

	if emptyCode != wrongCode {
		t.Fatalf("status codes differ: empty=%d wrong=%d — must be identical", emptyCode, wrongCode)
	}
	if len(emptyResp) != len(wrongResp) {
		t.Fatalf("response shapes differ: empty=%+v wrong=%+v", emptyResp, wrongResp)
	}
	for k, v := range emptyResp {
		if wrongResp[k] != v {
			t.Fatalf("response bodies differ: empty=%+v wrong=%+v", emptyResp, wrongResp)
		}
	}

	// Also genuinely malformed (not valid JSON at all), same route through the handler.
	gin.SetMode(gin.TestMode)
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodPost, "/api/v1/auth/gui-token/verify", bytes.NewReader([]byte("not json")))
	c.Request.Header.Set("Content-Type", "application/json")
	s.verifyGuiTokenHandler(c)

	if rec.Code != wrongCode {
		t.Fatalf("malformed-body status %d != wrong-token status %d", rec.Code, wrongCode)
	}
	var malformedResp map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &malformedResp); err != nil {
		t.Fatalf("decode malformed-body response %s: %v", rec.Body.String(), err)
	}
	if len(malformedResp) != len(wrongResp) {
		t.Fatalf("malformed-body shape %+v != wrong-token shape %+v", malformedResp, wrongResp)
	}
}

// TestVerifyGuiTokenHandler_SameResponseAcrossModes — B_174 (T_067). The matrix
// measured against the published v3.1.38 binary showed daemon mode answering
// {"required":false} to an empty POST body while server mode answered 400 "Token is
// required" for the exact same request. Establishing which was "correct" first (this
// ticket's own instruction, not converging toward whichever is easiest): NEITHER was.
// Daemon's answer was B_134's oracle — it read the wrong field (guiTokenHash, never
// set in daemon mode) and so reported "no auth needed" regardless of the token
// presented, even a wrong one. Server's 400 was a second, smaller oracle — it let a
// caller distinguish "no token sent" (400) from "wrong token sent" (200 valid:false).
// T_060 already fixed both by construction: verifyGuiTokenHandler is one function,
// shared unmodified by every api.Server regardless of which command constructs it, and
// it now reads currentGuiTokenHash() (hot-reload aware) with one consistent response
// shape for every non-matching input. This test proves that construction-level
// argument with actual execution: two Server values built EXACTLY the way daemon mode
// (SetGuiTokenDir only — StartEmbeddedGUI never calls SetGuiTokenHash) and server mode
// (SetGuiTokenHash only — runServer never calls SetGuiTokenDir) each really build one,
// on a fresh install (a hash exists — both modes call guitoken.EnsureHash
// unconditionally before serving, so the historical "hash never configured" case
// itself no longer applies to either mode's normal startup).
func TestVerifyGuiTokenHandler_SameResponseAcrossModes(t *testing.T) {
	dir := t.TempDir()
	token, err := guitoken.Generate()
	if err != nil {
		t.Fatalf("generate token: %v", err)
	}
	hash := guitoken.Hash(token)
	if err := guitoken.SaveHash(dir, hash); err != nil {
		t.Fatalf("save hash: %v", err)
	}

	daemonModeServer := &Server{config: config.Default(), logger: zap.NewNop(), guiTokenDir: dir}
	serverModeServer := &Server{config: config.Default(), logger: zap.NewNop(), guiTokenHash: hash}

	cases := []struct {
		name  string
		token string
	}{
		{"empty request (the matrix's own scenario)", ""},
		{"wrong token", "a-plausible-but-wrong-token"},
		{"the real token", token},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			daemonResp, daemonCode := postVerifyGuiToken(t, daemonModeServer, tc.token)
			serverResp, serverCode := postVerifyGuiToken(t, serverModeServer, tc.token)

			if daemonCode != serverCode {
				t.Fatalf("status differs: daemon=%d server=%d", daemonCode, serverCode)
			}
			if len(daemonResp) != len(serverResp) {
				t.Fatalf("response shapes differ: daemon=%+v server=%+v", daemonResp, serverResp)
			}
			for k, v := range daemonResp {
				if serverResp[k] != v {
					t.Fatalf("response bodies differ: daemon=%+v server=%+v", daemonResp, serverResp)
				}
			}
		})
	}
}
