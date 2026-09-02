package api

import (
	"encoding/json"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/config"
	"github.com/etcsec-com/etc-collector/internal/providers"
	"github.com/gin-gonic/gin"
)

func newRoutedServer(t *testing.T) *Server {
	t.Helper()
	gin.SetMode(gin.TestMode)
	// providers.NewManager() with nothing registered — Primary() returns nil,
	// so NewServer leaves s.engine nil, exactly the fresh-install/no-LDAP
	// state B_089's matrix row was measured against.
	s := NewServer(config.Default(), providers.NewManager())
	s.SetVersionInfo("3.1.39", "pro")
	return s
}

// TestCapabilitiesHandler_ReportsRealVersionAndDetectorCountWithNilEngine —
// B_089 (T_077). /api/v1/info/capabilities used to hardcode "version":
// "2.3.0" and report detectorCount as 0 whenever s.engine was nil — which it
// genuinely is on any install with no LDAP provider configured yet (verified:
// NewServer only builds an engine when manager.Primary() is non-nil, and this
// test's server has no provider registered). Neither is a live product fact:
// the binary is 3.1.x, and the detector catalog's size doesn't depend on
// whether a provider is connected — internal/api doesn't itself import the
// detector packages that populate audit.DefaultRegistry (that registration
// happens via blank imports in cmd/etc-collector, deliberately outside my
// jurisdiction), so this test can't observe a non-zero count directly. What
// it CAN and does prove: the handler no longer panics or special-cases a nil
// engine for this field, and echoes exactly len(audit.DefaultRegistry.All())
// — whatever that is in this process — rather than a hardcoded 0. The
// complementary TestCapabilitiesHandler_DetectorCountReadsRegistryNotEngine
// below statically proves the source is DefaultRegistry, not s.engine.
func TestCapabilitiesHandler_ReportsRealVersionAndDetectorCountWithNilEngine(t *testing.T) {
	s := newRoutedServer(t)
	if s.engine != nil {
		t.Fatal("test setup invalid: engine must be nil to reproduce B_089's exact state (no provider configured)")
	}

	// This route sits behind authMiddleware; calling the handler directly
	// proves what IT returns without also having to mint a real JWT here.
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodGet, "/api/v1/info/capabilities", nil)
	s.capabilitiesHandler(c)

	var body struct {
		Version       string `json:"version"`
		DetectorCount int    `json:"detectorCount"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if body.Version != "3.1.39" {
		t.Fatalf("version = %q, want %q (the version this test set via SetVersionInfo, not a hardcoded literal)", body.Version, "3.1.39")
	}
	wantCount := len(audit.DefaultRegistry.All())
	if body.DetectorCount != wantCount {
		t.Fatalf("detectorCount = %d, want %d (audit.DefaultRegistry.All(), the same catalog a live engine would report) — a nil engine must not force this to 0", body.DetectorCount, wantCount)
	}
}

// TestCapabilitiesHandler_DetectorCountReadsRegistryNotEngine — B_089
// (T_077), the teeth TestCapabilitiesHandler_ReportsRealVersionAndDetectorCountWithNilEngine
// can't provide on its own: internal/api's test binary never registers any
// real detectors (that only happens via cmd/etc-collector's blank imports),
// so len(audit.DefaultRegistry.All()) is 0 here regardless of which code path
// ran — a purely functional test can't tell the fixed handler apart from the
// old "0 when engine is nil" bug in this package. Static check instead:
// capabilitiesHandler's "detectorCount" field must be built from
// audit.DefaultRegistry, not from s.engine.
func TestCapabilitiesHandler_DetectorCountReadsRegistryNotEngine(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "handlers.go", nil, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse handlers.go: %v", err)
	}

	var fn *ast.FuncDecl
	for _, decl := range f.Decls {
		if fd, ok := decl.(*ast.FuncDecl); ok && fd.Name.Name == "capabilitiesHandler" {
			fn = fd
			break
		}
	}
	if fn == nil {
		t.Fatal("capabilitiesHandler not found in handlers.go")
	}

	var detectorCountExpr, versionExpr ast.Expr
	ast.Inspect(fn, func(n ast.Node) bool {
		lit, ok := n.(*ast.CompositeLit)
		if !ok {
			return true
		}
		for _, elt := range lit.Elts {
			kv, ok := elt.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			// gin.H is map[string]interface{}, so keys are string literals
			// ("detectorCount"), not identifiers — unlike a struct literal's
			// field names.
			keyLit, ok := kv.Key.(*ast.BasicLit)
			if !ok || keyLit.Kind != token.STRING {
				continue
			}
			switch strings.Trim(keyLit.Value, `"`) {
			case "detectorCount":
				detectorCountExpr = kv.Value
			case "version":
				versionExpr = kv.Value
			}
		}
		return true
	})

	if detectorCountExpr == nil {
		t.Fatal("no \"detectorCount\" field found in capabilitiesHandler's response")
	}
	var buf strings.Builder
	if err := format.Node(&buf, fset, detectorCountExpr); err != nil {
		t.Fatalf("render detectorCount expression: %v", err)
	}
	src := buf.String()
	if !strings.Contains(src, "DefaultRegistry") {
		t.Fatalf("detectorCount = %q, want it derived from audit.DefaultRegistry (available with no engine), not gated on a live engine", src)
	}
	if strings.Contains(src, "engine") {
		t.Fatalf("detectorCount = %q still references s.engine — this is exactly the nil-engine-means-0 bug B_089 closes", src)
	}

	if versionExpr == nil {
		t.Fatal("no \"version\" field found in capabilitiesHandler's response")
	}
	if _, isLiteral := versionExpr.(*ast.BasicLit); isLiteral {
		var vbuf strings.Builder
		format.Node(&vbuf, fset, versionExpr)
		t.Fatalf("version is a hardcoded literal %s — want s.version (the same field /health already reports correctly)", vbuf.String())
	}
}

// TestHealthAndCapabilities_NoEditionField — T_111. /health used to echo
// "edition": s.edition ("pro" on every build) even though v3.2.0 is a single
// unified binary with no edition split anymore — confirmed live on
// demo-collector-01 (curl -sk https://.../health -> {"edition":"pro",...})
// while LICENSING.md/README.md both describe one unified FSL license, so a
// client reading both public sources concluded the docs lied. capabilities
// never had the field (verified by reading handlers.go), but is asserted here
// too so the gap can't reopen silently on either endpoint.
func TestHealthAndCapabilities_NoEditionField(t *testing.T) {
	s := newRoutedServer(t)

	t.Run("/health", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/health", nil)
		s.router.ServeHTTP(rec, req)

		var body map[string]interface{}
		if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
			t.Fatalf("decode /health response: %v", err)
		}
		if _, present := body["edition"]; present {
			t.Fatalf("/health response still contains \"edition\": %v — v3.2.0 is a single unified binary, this field must not be exposed", body["edition"])
		}
	})

	t.Run("/api/v1/info/capabilities", func(t *testing.T) {
		rec := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(rec)
		c.Request = httptest.NewRequest(http.MethodGet, "/api/v1/info/capabilities", nil)
		s.capabilitiesHandler(c)

		var body map[string]interface{}
		if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
			t.Fatalf("decode /api/v1/info/capabilities response: %v", err)
		}
		if _, present := body["edition"]; present {
			t.Fatalf("/api/v1/info/capabilities response still contains \"edition\": %v — v3.2.0 is a single unified binary, this field must not be exposed", body["edition"])
		}
	})
}

// TestUnknownAPIRoute_Returns404NotSPA — B_090 (T_077). NoRoute used to
// unconditionally fall back to the embedded GUI's SPA handler, so a typo'd
// or removed /api/v1/* route returned 200 + HTML instead of 404 — a caller
// checking only the status code believes the request succeeded.
func TestUnknownAPIRoute_Returns404NotSPA(t *testing.T) {
	s := newRoutedServer(t)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/this-route-does-not-exist", nil)
	s.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("GET /api/v1/this-route-does-not-exist = %d, want 404 — got the SPA fallback if this is 200", rec.Code)
	}
	ct := rec.Header().Get("Content-Type")
	if ct == "" || ct[:9] != "applicati" {
		t.Fatalf("Content-Type = %q, want JSON — an HTML content type here means the SPA still answered", ct)
	}
}

// TestUnknownFrontendRoute_StillServesSPA — the SPA fallback is legitimate
// outside /api/ (client-side-routed frontend paths, e.g. deep-linking on
// refresh). B_090's fix must not turn every unmatched path into a 404.
func TestUnknownFrontendRoute_StillServesSPA(t *testing.T) {
	s := newRoutedServer(t)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/some/deep/frontend/route", nil)
	s.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /some/deep/frontend/route = %d, want 200 (SPA fallback) — B_090's fix must be scoped to /api/, not global", rec.Code)
	}
}

// TestNoWildcardCORSHeader — B_091 (T_077), second half. A blanket
// `Access-Control-Allow-Origin: *` on every response let any third-party
// page open in the administrator's browser drive this admin API
// cross-origin. The embedded GUI is always same-origin to this API, so no
// CORS header is needed at all; a cross-origin browser request should now be
// blocked by the browser's own same-origin policy instead of invited in.
func TestNoWildcardCORSHeader(t *testing.T) {
	s := newRoutedServer(t)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	s.router.ServeHTTP(rec, req)

	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("Access-Control-Allow-Origin = %q, want no CORS header at all", got)
	}
}
