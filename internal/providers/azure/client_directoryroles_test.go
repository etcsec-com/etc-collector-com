package azure

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/etcsec-com/etc-collector/pkg/types"
)

// PA_CUSTOM_ROLE_EXCESSIVE was permanently blind: /directoryRoles (the only
// endpoint GetDirectoryRoles queried) lists ACTIVATED built-in role
// instances only and every entry got IsBuiltIn forced to true, so the
// detector's `!role.IsBuiltIn` filter could never match anything, however
// many custom roles the tenant actually had. GetDirectoryRoles must merge
// in /roleManagement/directory/roleDefinitions, the resource that actually
// carries custom roles and a real isBuiltIn flag.

func newFakeDirectoryRolesServer(t *testing.T, directoryRolesBody, roleDefinitionsBody string, roleDefinitionsStatus int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/directoryRoles"):
			_, _ = w.Write([]byte(directoryRolesBody))
		case strings.HasSuffix(r.URL.Path, "/roleManagement/directory/roleDefinitions"):
			if roleDefinitionsStatus != 0 && roleDefinitionsStatus != http.StatusOK {
				w.WriteHeader(roleDefinitionsStatus)
				return
			}
			_, _ = w.Write([]byte(roleDefinitionsBody))
		default:
			http.NotFound(w, r)
		}
	}))
}

func TestGetDirectoryRoles_MergesCustomRoleDefinitions(t *testing.T) {
	directoryRolesBody := `{"value":[
		{"id":"activated-1","displayName":"Global Administrator","roleTemplateId":"62e90394-69f5-4237-9190-012177145e10"}
	]}`
	// Three definitions: the already-activated built-in above (must not be
	// duplicated), a built-in role never activated in this tenant (must be
	// left out - GetDirectoryRoles' contract is "roles this tenant actually
	// has instantiated"), and one genuine custom role.
	roleDefinitionsBody := `{"value":[
		{"id":"62e90394-69f5-4237-9190-012177145e10","displayName":"Global Administrator","isBuiltIn":true},
		{"id":"fe930be7-5e62-47db-91af-98c3a49a38b1","displayName":"User Administrator","isBuiltIn":true},
		{"id":"custom-role-1","displayName":"Contoso Helpdesk Tier 2","description":"Tenant-defined custom role","isBuiltIn":false}
	]}`

	server := newFakeDirectoryRolesServer(t, directoryRolesBody, roleDefinitionsBody, http.StatusOK)
	defer server.Close()

	client := &Client{connected: true, cred: fakeTokenCredential{}, graphBaseURL: server.URL + "/"}
	roles, err := client.GetDirectoryRoles(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(roles) != 2 {
		t.Fatalf("got %d roles, want 2 (1 activated built-in + 1 custom): %+v", len(roles), roles)
	}

	byID := make(map[string]types.DirectoryRole, len(roles))
	for _, r := range roles {
		byID[r.ID] = r
	}
	if _, ok := byID["activated-1"]; !ok {
		t.Errorf("activated built-in role missing from result: %+v", roles)
	}
	custom, ok := byID["custom-role-1"]
	if !ok {
		t.Fatalf("custom role custom-role-1 missing from result: %+v", roles)
	}
	if custom.IsBuiltIn {
		t.Error("custom role must have IsBuiltIn = false - this is the whole point of the fix")
	}
	if custom.RoleTemplateID != "custom-role-1" {
		t.Errorf("custom role RoleTemplateID = %q, want its own id (custom roles have no template; roleAssignment.roleDefinitionId references the definition id directly)", custom.RoleTemplateID)
	}
	if !custom.IsEnabled {
		t.Error("custom role must have IsEnabled = true (directly assignable, no activation step)")
	}
}

func TestGetDirectoryRoles_RoleDefinitionsEndpointDenied_FallsBackToBuiltInOnly(t *testing.T) {
	directoryRolesBody := `{"value":[
		{"id":"activated-1","displayName":"Global Administrator","roleTemplateId":"62e90394-69f5-4237-9190-012177145e10"}
	]}`
	server := newFakeDirectoryRolesServer(t, directoryRolesBody, "", http.StatusForbidden)
	defer server.Close()

	client := &Client{connected: true, cred: fakeTokenCredential{}, graphBaseURL: server.URL + "/"}
	roles, err := client.GetDirectoryRoles(context.Background())
	if err != nil {
		t.Fatalf("missing RoleManagement.Read.Directory must not fail the whole call (best-effort), got: %v", err)
	}
	if len(roles) != 1 || roles[0].ID != "activated-1" {
		t.Fatalf("got %+v, want just the built-in activated role", roles)
	}
	if !roles[0].IsBuiltIn {
		t.Error("built-in activated role must keep IsBuiltIn = true")
	}
}

func TestGetDirectoryRoles_DirectoryRolesEndpointFails(t *testing.T) {
	server := newFakeDirectoryRolesServer(t, "", "", http.StatusOK)
	server.Close() // unreachable, forces a transport error on /directoryRoles itself

	client := &Client{connected: true, cred: fakeTokenCredential{}, graphBaseURL: server.URL + "/"}
	// Short timeout: an unreachable server otherwise triggers callGraphHTTP's
	// full retry/backoff ladder (~15s) before giving up.
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if _, err := client.GetDirectoryRoles(ctx); err == nil {
		t.Error("expected an error when /directoryRoles itself is unreachable")
	}
}
