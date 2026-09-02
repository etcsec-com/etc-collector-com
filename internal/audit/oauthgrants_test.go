package audit

import (
	"reflect"
	"sort"
	"testing"

	"github.com/etcsec-com/etc-collector/pkg/types"
)

func TestEnrichOAuth2Grants_ResolvesNamesAndAppID(t *testing.T) {
	sps := []types.ServicePrincipal{
		{ID: "sp-client-1", AppID: "app-1", DisplayName: "Acme App"},
		{ID: "sp-resource-graph", AppID: types.MicrosoftGraphAppID, DisplayName: "Microsoft Graph"},
	}
	grants := []types.OAuth2PermissionGrant{
		{ID: "g1", ClientID: "sp-client-1", ResourceID: "sp-resource-graph", ConsentType: "Principal", Scope: "User.Read offline_access"},
	}
	EnrichOAuth2Grants(grants, sps)
	g := grants[0]
	if g.ClientName != "Acme App" || g.ClientAppID != "app-1" {
		t.Errorf("client resolve mismatch: name=%q appID=%q", g.ClientName, g.ClientAppID)
	}
	if g.ResourceName != "Microsoft Graph" {
		t.Errorf("resource resolve mismatch: %q", g.ResourceName)
	}
	if !reflect.DeepEqual(g.Scopes, []string{"User.Read", "offline_access"}) {
		t.Errorf("Scopes parse mismatch: %v", g.Scopes)
	}
	if g.IsDangerous {
		t.Errorf("User.Read + offline_access should NOT be dangerous; got IsDangerous=true with scopes=%v", g.DangerousScopes)
	}
}

func TestEnrichOAuth2Grants_DangerousScopeFlagging(t *testing.T) {
	grants := []types.OAuth2PermissionGrant{
		{ID: "g1", Scope: "Mail.Read User.Read"},
		{ID: "g2", Scope: "Mail.ReadWrite Files.ReadWrite.All"},
		{ID: "g3", Scope: "User.Read offline_access"},
		{ID: "g4", Scope: ""}, // empty — must not crash
	}
	EnrichOAuth2Grants(grants, nil)

	if !grants[0].IsDangerous || !reflect.DeepEqual(grants[0].DangerousScopes, []string{"Mail.Read"}) {
		t.Errorf("g1 dangerous mismatch: IsDang=%v scopes=%v", grants[0].IsDangerous, grants[0].DangerousScopes)
	}
	got := append([]string(nil), grants[1].DangerousScopes...)
	sort.Strings(got)
	want := []string{"Files.ReadWrite.All", "Mail.ReadWrite"}
	if !grants[1].IsDangerous || !reflect.DeepEqual(got, want) {
		t.Errorf("g2 dangerous mismatch: IsDang=%v scopes=%v", grants[1].IsDangerous, grants[1].DangerousScopes)
	}
	if grants[2].IsDangerous || len(grants[2].DangerousScopes) != 0 {
		t.Errorf("g3 should not be dangerous: %v", grants[2].DangerousScopes)
	}
	if len(grants[3].Scopes) != 0 || grants[3].IsDangerous {
		t.Errorf("g4 empty-scope handling mismatch: scopes=%v dang=%v", grants[3].Scopes, grants[3].IsDangerous)
	}
}

func TestEnrichOAuth2Grants_NilSPsDoesNotPanic(t *testing.T) {
	grants := []types.OAuth2PermissionGrant{
		{ID: "g1", ClientID: "missing-client", ResourceID: "missing-resource", Scope: "Directory.ReadWrite.All"},
	}
	EnrichOAuth2Grants(grants, nil)
	if grants[0].ClientName != "" || grants[0].ResourceName != "" {
		t.Errorf("nil SP cache should leave name fields empty")
	}
	if !grants[0].IsDangerous {
		t.Errorf("Directory.ReadWrite.All should be flagged dangerous even without SP cache")
	}
}

func TestSummarizeOAuthGrants(t *testing.T) {
	grants := []types.OAuth2PermissionGrant{
		{ID: "g1", ConsentType: "Principal", IsDangerous: true},
		{ID: "g2", ConsentType: "Principal"},
		{ID: "g3", ConsentType: "AllPrincipals", IsDangerous: true},
		{ID: "g4", ConsentType: "AllPrincipals"},
		{ID: "g5", ConsentType: ""}, // unknown consent type — must not crash
	}
	s := SummarizeOAuthGrants(grants)
	if s.TotalGrants != 5 {
		t.Errorf("TotalGrants=%d want 5", s.TotalGrants)
	}
	if s.ByConsentType["Principal"] != 2 || s.ByConsentType["AllPrincipals"] != 2 {
		t.Errorf("ByConsentType mismatch: %v", s.ByConsentType)
	}
	if _, hasEmpty := s.ByConsentType[""]; hasEmpty {
		t.Errorf("empty consent type should not create a bucket: %v", s.ByConsentType)
	}
	if s.DangerousCount != 2 {
		t.Errorf("DangerousCount=%d want 2", s.DangerousCount)
	}
	if len(s.Grants) != 5 {
		t.Errorf("Grants slice should be passed through (len=%d, want 5)", len(s.Grants))
	}
}

func TestSummarizeOAuthGrants_Empty(t *testing.T) {
	s := SummarizeOAuthGrants(nil)
	if s == nil || s.TotalGrants != 0 || s.DangerousCount != 0 {
		t.Errorf("nil input should produce zero summary, got %#v", s)
	}
}
