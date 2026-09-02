package api

import (
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

// TestSlidingWindowLimiter_AllowsUpToMaxThenBlocks — B_137 (T_081) core
// logic, with an injected clock so this never depends on wall-clock sleeps.
func TestSlidingWindowLimiter_AllowsUpToMaxThenBlocks(t *testing.T) {
	now := time.Date(2026, 8, 27, 0, 0, 0, 0, time.UTC)
	l := newSlidingWindowLimiter(3, time.Minute)
	l.now = func() time.Time { return now }

	for i := 0; i < 3; i++ {
		if !l.Allow() {
			t.Fatalf("call %d should be allowed (within max)", i+1)
		}
	}
	if l.Allow() {
		t.Fatal("4th call within the same window must be blocked")
	}
}

// TestSlidingWindowLimiter_WindowSlides — capacity frees up once the oldest
// hits fall outside the window, so this doesn't become a permanent lockout.
func TestSlidingWindowLimiter_WindowSlides(t *testing.T) {
	now := time.Date(2026, 8, 27, 0, 0, 0, 0, time.UTC)
	l := newSlidingWindowLimiter(1, time.Minute)
	l.now = func() time.Time { return now }

	if !l.Allow() {
		t.Fatal("first call should be allowed")
	}
	if l.Allow() {
		t.Fatal("second call inside the window must be blocked")
	}

	now = now.Add(time.Minute + time.Second)
	if !l.Allow() {
		t.Fatal("a call after the window has fully elapsed must be allowed again")
	}
}

// TestRateLimitMiddleware_BlocksAfterLimit — B_137 (T_081). Drives the real
// middleware (not just the limiter type) through gin, proving
// POST /api/v1/auth/token actually gets capped end to end.
func TestRateLimitMiddleware_BlocksAfterLimit(t *testing.T) {
	gin.SetMode(gin.TestMode)

	now := time.Date(2026, 8, 27, 0, 0, 0, 0, time.UTC)
	limiter := newSlidingWindowLimiter(2, time.Minute)
	limiter.now = func() time.Time { return now }
	s := &Server{tokenIssuanceLimiter: limiter}

	newCtx := func() (*httptest.ResponseRecorder, *gin.Context) {
		rec := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(rec)
		c.Request = httptest.NewRequest(http.MethodPost, "/api/v1/auth/token", nil)
		return rec, c
	}

	for i := 0; i < 2; i++ {
		rec, c := newCtx()
		s.rateLimitMiddleware()(c)
		if c.IsAborted() {
			t.Fatalf("request %d should pass, got aborted with %d", i+1, rec.Code)
		}
	}

	rec, c := newCtx()
	s.rateLimitMiddleware()(c)
	if !c.IsAborted() {
		t.Fatal("the 3rd request within the window must be blocked")
	}
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("got status %d, want 429", rec.Code)
	}
}

// TestTokenRequest_MaxUsesFieldRemoved — B_137 (T_081). maxUses used to be
// accepted here and threaded into the signed JWT's claims, but nothing ever
// enforced it (no per-token usage-counting store exists in this codebase —
// JWTs are validated by signature + exp only). A field that implies a
// control it doesn't provide is worse than no field: assert it's actually
// gone from the request type, not just unused.
func TestTokenRequest_MaxUsesFieldRemoved(t *testing.T) {
	typ := reflect.TypeOf(TokenRequest{})
	for i := 0; i < typ.NumField(); i++ {
		if strings.EqualFold(typ.Field(i).Name, "MaxUses") {
			t.Fatalf("TokenRequest still has a MaxUses field (%s) — this ticket removed it because nothing enforces it", typ.Field(i).Name)
		}
	}
}

// TestTokenRouteHasRateLimitMiddleware — B_137 (T_081), a wiring lock:
// static proof that POST /api/v1/auth/token's route registration in
// server.go actually includes rateLimitMiddleware as a handler, not just
// that the middleware function exists somewhere unused (that was the exact
// state of the pre-existing rateLimitMiddleware placeholder).
func TestTokenRouteHasRateLimitMiddleware(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "server.go", nil, 0)
	if err != nil {
		t.Fatalf("parse server.go: %v", err)
	}

	found := false
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "POST" {
			return true
		}
		if len(call.Args) == 0 {
			return true
		}
		lit, ok := call.Args[0].(*ast.BasicLit)
		if !ok || lit.Value != `"/token"` {
			return true
		}
		for _, arg := range call.Args[1:] {
			argSel, ok := arg.(*ast.CallExpr)
			if !ok {
				continue
			}
			if fnSel, ok := argSel.Fun.(*ast.SelectorExpr); ok && fnSel.Sel.Name == "rateLimitMiddleware" {
				found = true
			}
		}
		return true
	})

	if !found {
		t.Fatal(`POST "/token" route registration does not include s.rateLimitMiddleware() — token issuance would be unbounded again`)
	}
}
