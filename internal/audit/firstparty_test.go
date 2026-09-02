package audit

import (
	"testing"

	"github.com/etcsec-com/etc-collector/pkg/types"
)

// helper — build a User with the Azure fields the helper inspects.
func mkFirstPartyUser(upn, displayName, creationType string, syncedFromAD bool) types.User {
	u := types.User{
		ObjectSID:         "id-" + upn,
		UserPrincipalName: upn,
		DisplayName:       displayName,
	}
	if creationType != "" {
		ct := creationType
		u.AzureCreationType = &ct
	}
	if syncedFromAD {
		t := true
		u.AzureOnPremisesSyncEnabled = &t
	}
	enabled := true
	u.AzureAccountEnabled = &enabled
	return u
}

func TestBuildFirstPartyAccountsSummary_NilData(t *testing.T) {
	if got := BuildFirstPartyAccountsSummary(nil, "test"); got != nil {
		t.Errorf("expected nil on nil data, got %+v", got)
	}
}

func TestBuildFirstPartyAccountsSummary_NoUsers(t *testing.T) {
	d := &DetectorData{Users: nil}
	got := BuildFirstPartyAccountsSummary(d, "v3.1.39")
	if got == nil {
		t.Fatal("summary should not be nil even with empty Users")
	}
	if got.TotalDetected != 0 {
		t.Errorf("TotalDetected = %d, want 0", got.TotalDetected)
	}
	if got.ByCreationType == nil {
		t.Error("ByCreationType must be initialised even when empty")
	}
	if got.CollectorVersion != "v3.1.39" {
		t.Errorf("CollectorVersion = %q, want v3.1.39", got.CollectorVersion)
	}
}

func TestBuildFirstPartyAccountsSummary_UPNMatchOnly(t *testing.T) {
	// Bookings + Forms + svc accounts (creationType empty / unset)
	d := &DetectorData{Users: []types.User{
		mkFirstPartyUser("bookings-myorg@example.onmicrosoft.com", "Bookings", "", false),
		mkFirstPartyUser("forms-pro@example.onmicrosoft.com", "Forms Pro", "", false),
		mkFirstPartyUser("svc-printer@example.onmicrosoft.com", "Print Svc", "", false),
		mkFirstPartyUser("real.human@example.onmicrosoft.com", "Real Human", "", false),
	}}
	got := BuildFirstPartyAccountsSummary(d, "v3.1.39")
	if got.TotalDetected != 3 {
		t.Errorf("TotalDetected = %d, want 3", got.TotalDetected)
	}
	// Sorted by UPN.
	wantUPNs := []string{
		"bookings-myorg@example.onmicrosoft.com",
		"forms-pro@example.onmicrosoft.com",
		"svc-printer@example.onmicrosoft.com",
	}
	for i, want := range wantUPNs {
		if got.Accounts[i].UserPrincipalName != want {
			t.Errorf("Accounts[%d].UPN = %q, want %q", i, got.Accounts[i].UserPrincipalName, want)
		}
	}
	// matchPattern must be set, not creationType.
	for _, a := range got.Accounts {
		if a.MatchPattern == "" {
			t.Errorf("MatchPattern empty for %s", a.UserPrincipalName)
		}
		if a.CreationType != "" {
			t.Errorf("CreationType should be empty for UPN-match-only, got %q", a.CreationType)
		}
	}
	// All 3 buckets land in "Other" (no real creationType).
	if got.ByCreationType["Other"] != 3 {
		t.Errorf("Other bucket = %d, want 3 (got %+v)", got.ByCreationType["Other"], got.ByCreationType)
	}
}

func TestBuildFirstPartyAccountsSummary_CreationTypeMatchOnly(t *testing.T) {
	// User with creationType=Resource but a UPN that doesn't match any pattern.
	d := &DetectorData{Users: []types.User{
		mkFirstPartyUser("workspace-account@example.onmicrosoft.com", "Workspace", "Resource", false),
		mkFirstPartyUser("guest-signup@example.onmicrosoft.com", "Self-service guest", "EmailVerified", false),
		mkFirstPartyUser("regular@example.onmicrosoft.com", "Regular user", "", false), // empty + no UPN match → not flagged
	}}
	got := BuildFirstPartyAccountsSummary(d, "v3.1.39")
	if got.TotalDetected != 2 {
		t.Errorf("TotalDetected = %d, want 2", got.TotalDetected)
	}
	if got.ByCreationType["Resource"] != 1 {
		t.Errorf("Resource bucket = %d, want 1", got.ByCreationType["Resource"])
	}
	if got.ByCreationType["EmailVerified"] != 1 {
		t.Errorf("EmailVerified bucket = %d, want 1", got.ByCreationType["EmailVerified"])
	}
	// matchPattern empty (only creationType triggered).
	for _, a := range got.Accounts {
		if a.MatchPattern != "" {
			t.Errorf("MatchPattern should be empty, got %q for %s", a.MatchPattern, a.UserPrincipalName)
		}
		if a.CreationType == "" {
			t.Errorf("CreationType should be populated, got empty for %s", a.UserPrincipalName)
		}
	}
}

func TestBuildFirstPartyAccountsSummary_CloudOnlyFilter(t *testing.T) {
	// Synced (onPremisesSyncEnabled=true) accounts must be skipped even
	// if they match a UPN pattern — "svc-printer" can be a real on-prem
	// service account that should NOT be flagged as cloud orphan.
	d := &DetectorData{Users: []types.User{
		mkFirstPartyUser("bookings-onprem@example.com", "Synced Bookings", "Resource", true),
		mkFirstPartyUser("svc-onprem@example.com", "Synced Svc", "", true),
		mkFirstPartyUser("bookings-cloud@example.onmicrosoft.com", "Cloud Bookings", "", false),
	}}
	got := BuildFirstPartyAccountsSummary(d, "v3.1.39")
	if got.TotalDetected != 1 {
		t.Errorf("TotalDetected = %d, want 1 (only the cloud Bookings)", got.TotalDetected)
	}
	if got.Accounts[0].UserPrincipalName != "bookings-cloud@example.onmicrosoft.com" {
		t.Errorf("wrong account flagged: %s", got.Accounts[0].UserPrincipalName)
	}
}

func TestBuildFirstPartyAccountsSummary_BothMatchSignals(t *testing.T) {
	// Both creationType=Resource AND UPN matches "bookings*". The output
	// carries both fields — SaaS analyzer can decide priority.
	d := &DetectorData{Users: []types.User{
		mkFirstPartyUser("bookings-myorg@example.onmicrosoft.com", "Bookings Resource", "Resource", false),
	}}
	got := BuildFirstPartyAccountsSummary(d, "v3.1.39")
	if got.TotalDetected != 1 {
		t.Fatalf("TotalDetected = %d, want 1", got.TotalDetected)
	}
	a := got.Accounts[0]
	if a.MatchPattern != "bookings" {
		t.Errorf("MatchPattern = %q, want bookings", a.MatchPattern)
	}
	if a.CreationType != "Resource" {
		t.Errorf("CreationType = %q, want Resource", a.CreationType)
	}
	if got.ByCreationType["Resource"] != 1 {
		t.Errorf("Resource bucket = %d, want 1", got.ByCreationType["Resource"])
	}
}
