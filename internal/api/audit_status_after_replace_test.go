package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/config"
	"github.com/etcsec-com/etc-collector/internal/providers"
	"github.com/etcsec-com/etc-collector/pkg/types"
	"github.com/gin-gonic/gin"
)

// stubProvider is a minimal providers.Provider for handler-level tests —
// exercises the real manager.Replace() -> auditStatusHandler path without a
// live directory.
type stubProvider struct {
	ptype providers.ProviderType
}

func (p *stubProvider) Type() providers.ProviderType                { return p.ptype }
func (p *stubProvider) Connect(ctx context.Context) error           { return nil }
func (p *stubProvider) Close() error                                { return nil }
func (p *stubProvider) IsConnected() bool                           { return true }
func (p *stubProvider) GetUsers(ctx context.Context, opts providers.QueryOptions) ([]types.User, error) {
	return nil, nil
}
func (p *stubProvider) GetGroups(ctx context.Context, opts providers.QueryOptions) ([]types.Group, error) {
	return nil, nil
}
func (p *stubProvider) GetComputers(ctx context.Context, opts providers.QueryOptions) ([]types.Computer, error) {
	return nil, nil
}
func (p *stubProvider) GetDomainInfo(ctx context.Context) (*types.DomainInfo, error) {
	return &types.DomainInfo{}, nil
}

// TestAuditStatusHandler_ReadyAfterLDAPReplace — T_138 defect 1. qa measured
// live against DC01 (T_137, docs/rejeu-doc/qa/BILAN.md A#13): start the
// server with no LDAP, PUT /api/v1/admin/config/ldap (200, connected), then
// GET /api/v1/audit/ad/status still answered {"status":"not_configured",
// "provider":null} in a loop, even though POST /api/v1/audit/ad succeeded in
// the same process. Root cause: updateLDAPConfigHandler (admin.go:195, the
// standalone-mode branch, no onConfigUpdate callback) calls manager.Replace()
// first, which never set m.primary — only manager.Register() did — and
// auditStatusHandler reads manager.Primary(). This reproduces that exact
// call: Replace() on a fresh manager, then the status handler, with no real
// LDAP connection involved.
func TestAuditStatusHandler_ReadyAfterLDAPReplace(t *testing.T) {
	gin.SetMode(gin.TestMode)

	manager := providers.NewManager()
	s := NewServer(config.Default(), manager)
	s.SetVersionInfo("3.1.39", "pro")

	ldap := &stubProvider{ptype: providers.ProviderTypeLDAP}
	if err := manager.Replace(ldap); err != nil {
		t.Fatalf("manager.Replace: %v", err)
	}

	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodGet, "/api/v1/audit/ad/status", nil)
	s.auditStatusHandler(c)

	var body struct {
		Status   string `json:"status"`
		Provider string `json:"provider"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.Status != "ready" {
		t.Fatalf(`status = %q, want "ready" — manager.Replace() must set primary so this reflects the provider that was just configured, not lie forever`, body.Status)
	}
	if body.Provider != string(providers.ProviderTypeLDAP) {
		t.Fatalf("provider = %q, want %q", body.Provider, providers.ProviderTypeLDAP)
	}
}
