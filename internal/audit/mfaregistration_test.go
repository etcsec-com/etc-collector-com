package audit

import (
	"testing"

	"github.com/etcsec-com/etc-collector/pkg/types"
)

// helper — build a CA policy targeting the MFA registration user action,
// with optional location/grant conditions.
func mkMFARegPolicy(id, name, state string, includeLocations []string, grants []string) types.ConditionalAccessPolicyDetail {
	p := types.ConditionalAccessPolicyDetail{
		ID:          id,
		DisplayName: name,
		State:       state,
		Conditions: &types.CADetailConditions{
			Applications: &types.CADetailApplications{
				IncludeUserActions: []string{mfaRegistrationUserAction},
			},
		},
	}
	if includeLocations != nil {
		p.Conditions.Locations = &types.CADetailLocations{
			IncludeLocations: includeLocations,
		}
	}
	if grants != nil {
		p.GrantControls = &types.CADetailGrantControls{
			BuiltInControls: grants,
		}
	}
	return p
}

func TestBuildMFARegistrationPolicySummary_NilData(t *testing.T) {
	if got := BuildMFARegistrationPolicySummary(nil, "test"); got != nil {
		t.Errorf("expected nil on nil data, got %+v", got)
	}
}

func TestBuildMFARegistrationPolicySummary_ScopeMissing(t *testing.T) {
	d := &DetectorData{} // CA detail slice nil
	got := BuildMFARegistrationPolicySummary(d, "v3.1.39")
	if got.Available {
		t.Error("Available should be false when CA detail slice is nil")
	}
	if got.Reason == "" {
		t.Error("Reason must be populated when Available=false")
	}
	if got.PoliciesFound != 0 {
		t.Errorf("PoliciesFound = %d, want 0", got.PoliciesFound)
	}
}

func TestBuildMFARegistrationPolicySummary_NoMFARegPolicy(t *testing.T) {
	// CA detail slice present but no policy targets the MFA registration
	// user action → PoliciesFound stays 0.
	d := &DetectorData{
		AzureConditionalAccessPolicyDetails: []types.ConditionalAccessPolicyDetail{
			{
				ID:    "ca-block-legacy",
				State: "enabled",
				Conditions: &types.CADetailConditions{
					Applications: &types.CADetailApplications{
						IncludeApplications: []string{"All"},
					},
				},
			},
		},
	}
	got := BuildMFARegistrationPolicySummary(d, "v3.1.39")
	if !got.Available {
		t.Error("Available should be true")
	}
	if got.PoliciesFound != 0 {
		t.Errorf("PoliciesFound = %d, want 0", got.PoliciesFound)
	}
	if got.EnrollmentRestrictedToTrustedLocations {
		t.Error("EnrollmentRestrictedToTrustedLocations should be false")
	}
	if len(got.Policies) != 0 {
		t.Errorf("Policies should be empty, got %d", len(got.Policies))
	}
}

func TestBuildMFARegistrationPolicySummary_NonRestrictedPolicy(t *testing.T) {
	// MFA registration policy targeting "All" locations → not restricted.
	d := &DetectorData{
		AzureConditionalAccessPolicyDetails: []types.ConditionalAccessPolicyDetail{
			mkMFARegPolicy("p1", "MFA Reg — All Users", "enabled", []string{"All"}, []string{"mfa"}),
		},
	}
	got := BuildMFARegistrationPolicySummary(d, "v3.1.39")
	if got.PoliciesFound != 1 {
		t.Errorf("PoliciesFound = %d, want 1", got.PoliciesFound)
	}
	if got.EnrollmentRestrictedToTrustedLocations {
		t.Error("EnrollmentRestrictedToTrustedLocations should be false (All locations)")
	}
	if len(got.Policies[0].UserActions) == 0 || got.Policies[0].UserActions[0] != mfaRegistrationUserAction {
		t.Errorf("UserActions = %v", got.Policies[0].UserActions)
	}
}

func TestBuildMFARegistrationPolicySummary_AllTrustedPolicy(t *testing.T) {
	// Policy with IncludeLocations: ["AllTrusted"] → restricted regardless
	// of how many trusted locations are defined on the tenant.
	d := &DetectorData{
		AzureConditionalAccessPolicyDetails: []types.ConditionalAccessPolicyDetail{
			mkMFARegPolicy("p1", "MFA Reg Trusted-only", "enabled", []string{"AllTrusted"}, []string{"mfa"}),
		},
		AzureNamedLocations: []types.NamedLocation{
			{ID: "loc-paris", DisplayName: "Paris HQ", IsTrusted: true},
			{ID: "loc-public", DisplayName: "Public WiFi", IsTrusted: false},
		},
	}
	got := BuildMFARegistrationPolicySummary(d, "v3.1.39")
	if got.TrustedLocationCount != 1 {
		t.Errorf("TrustedLocationCount = %d, want 1", got.TrustedLocationCount)
	}
	if !got.EnrollmentRestrictedToTrustedLocations {
		t.Error("EnrollmentRestrictedToTrustedLocations should be true (AllTrusted)")
	}
	if !got.Policies[0].RestrictedToTrustedLocations {
		t.Error("policy entry should report RestrictedToTrustedLocations=true")
	}
}

func TestBuildMFARegistrationPolicySummary_SpecificTrustedGUIDs(t *testing.T) {
	// Policy includes only specific GUIDs, all of which resolve to trusted.
	d := &DetectorData{
		AzureConditionalAccessPolicyDetails: []types.ConditionalAccessPolicyDetail{
			mkMFARegPolicy("p1", "MFA Reg HQ", "enabled", []string{"loc-paris", "loc-london"}, []string{"mfa"}),
		},
		AzureNamedLocations: []types.NamedLocation{
			{ID: "loc-paris", DisplayName: "Paris HQ", IsTrusted: true},
			{ID: "loc-london", DisplayName: "London office", IsTrusted: true},
			{ID: "loc-public", DisplayName: "Public WiFi", IsTrusted: false},
		},
	}
	got := BuildMFARegistrationPolicySummary(d, "v3.1.39")
	if !got.EnrollmentRestrictedToTrustedLocations {
		t.Error("expected restricted (both GUIDs resolve to trusted)")
	}
	if got.TrustedLocationCount != 2 {
		t.Errorf("TrustedLocationCount = %d, want 2", got.TrustedLocationCount)
	}
}

func TestBuildMFARegistrationPolicySummary_OneUntrustedGUIDPoisons(t *testing.T) {
	// Two GUIDs: one trusted, one not. The non-trusted one poisons the
	// set → policy is NOT restricted.
	d := &DetectorData{
		AzureConditionalAccessPolicyDetails: []types.ConditionalAccessPolicyDetail{
			mkMFARegPolicy("p1", "Mixed locations", "enabled", []string{"loc-paris", "loc-public"}, []string{"mfa"}),
		},
		AzureNamedLocations: []types.NamedLocation{
			{ID: "loc-paris", DisplayName: "Paris HQ", IsTrusted: true},
			{ID: "loc-public", DisplayName: "Public WiFi", IsTrusted: false},
		},
	}
	got := BuildMFARegistrationPolicySummary(d, "v3.1.39")
	if got.EnrollmentRestrictedToTrustedLocations {
		t.Error("expected NOT restricted (one of the GUIDs is non-trusted)")
	}
	if got.PoliciesFound != 1 {
		t.Errorf("PoliciesFound = %d, want 1", got.PoliciesFound)
	}
}

func TestBuildMFARegistrationPolicySummary_DisabledPolicyNotCounted(t *testing.T) {
	// Disabled policies appear in Policies[] but do NOT count toward
	// PoliciesFound or the top-level restriction flag.
	d := &DetectorData{
		AzureConditionalAccessPolicyDetails: []types.ConditionalAccessPolicyDetail{
			mkMFARegPolicy("p1", "Disabled MFA Reg", "disabled", []string{"AllTrusted"}, []string{"mfa"}),
		},
	}
	got := BuildMFARegistrationPolicySummary(d, "v3.1.39")
	if got.PoliciesFound != 0 {
		t.Errorf("PoliciesFound = %d, want 0 (policy is disabled)", got.PoliciesFound)
	}
	if got.EnrollmentRestrictedToTrustedLocations {
		t.Error("flag should be false — disabled policies don't restrict anything")
	}
	if len(got.Policies) != 1 {
		t.Errorf("Policies should still surface the disabled policy, got %d", len(got.Policies))
	}
}

func TestBuildMFARegistrationPolicySummary_DeterministicSort(t *testing.T) {
	d := &DetectorData{
		AzureConditionalAccessPolicyDetails: []types.ConditionalAccessPolicyDetail{
			mkMFARegPolicy("p2", "Zeta policy", "enabled", []string{"All"}, nil),
			mkMFARegPolicy("p1", "Alpha policy", "enabled", []string{"All"}, nil),
		},
	}
	got := BuildMFARegistrationPolicySummary(d, "v3.1.39")
	if got.Policies[0].DisplayName != "Alpha policy" {
		t.Errorf("expected Alpha first, got %s", got.Policies[0].DisplayName)
	}
}
