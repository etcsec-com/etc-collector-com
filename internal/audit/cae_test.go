package audit

import (
	"testing"

	"github.com/etcsec-com/etc-collector/pkg/types"
)

// helper — build a CA detail policy with a CAE mode + included apps.
func mkCAEPolicy(id, name, state, mode string, includeApps []string, disableResilience *bool) types.ConditionalAccessPolicyDetail {
	p := types.ConditionalAccessPolicyDetail{
		ID:          id,
		DisplayName: name,
		State:       state,
	}
	if mode != "" {
		p.SessionControls = &types.CADetailSessionControls{
			ContinuousAccessEvaluation: &types.CADetailContinuousAccessEvaluation{
				Mode:      mode,
				IsEnabled: mode == types.CAEModeStrictEnforcement,
			},
			DisableResilienceDefaults: disableResilience,
		}
	} else if disableResilience != nil {
		p.SessionControls = &types.CADetailSessionControls{
			DisableResilienceDefaults: disableResilience,
		}
	}
	if includeApps != nil {
		p.Conditions = &types.CADetailConditions{
			Applications: &types.CADetailApplications{
				IncludeApplications: includeApps,
			},
		}
	}
	return p
}

func TestBuildCAESummary_NilData(t *testing.T) {
	if got := BuildCAESummary(nil, "test"); got != nil {
		t.Errorf("expected nil summary on nil data, got %+v", got)
	}
}

func TestBuildCAESummary_ScopeMissing(t *testing.T) {
	d := &DetectorData{} // AzureConditionalAccessPolicyDetails == nil
	got := BuildCAESummary(d, "v3.1.39")
	if got == nil {
		t.Fatal("expected summary, got nil")
	}
	if got.Available {
		t.Error("Available must be false when CA detail slice is nil")
	}
	if got.Reason == "" {
		t.Error("Reason must be populated when Available=false")
	}
	if got.PoliciesTotal != 0 || got.PoliciesWithCAE != 0 {
		t.Errorf("counters must be zero, got total=%d withCAE=%d", got.PoliciesTotal, got.PoliciesWithCAE)
	}
}

func TestBuildCAESummary_NoAdoption(t *testing.T) {
	// 3 policies, none with CAE strict.
	d := &DetectorData{
		AzureConditionalAccessPolicyDetails: []types.ConditionalAccessPolicyDetail{
			mkCAEPolicy("p1", "Policy 1", "enabled", "", []string{"All"}, nil),
			mkCAEPolicy("p2", "Policy 2", "enabled", types.CAEModeDisabled, []string{"Office365"}, nil),
			mkCAEPolicy("p3", "Policy 3", "disabled", types.CAEModeStrictEnforcement, []string{"All"}, nil),
		},
	}
	got := BuildCAESummary(d, "v3.1.39")
	if !got.Available {
		t.Error("Available should be true")
	}
	if got.GloballyEnabled {
		t.Error("GloballyEnabled should be false (p3 is disabled, p2 is mode=disabled)")
	}
	if got.PoliciesWithCAE != 0 {
		t.Errorf("PoliciesWithCAE = %d, want 0", got.PoliciesWithCAE)
	}
	if got.PoliciesEnabledTotal != 2 {
		t.Errorf("PoliciesEnabledTotal = %d, want 2", got.PoliciesEnabledTotal)
	}
	if got.PoliciesTotal != 3 {
		t.Errorf("PoliciesTotal = %d, want 3", got.PoliciesTotal)
	}
	if got.AdoptionPercent != 0 {
		t.Errorf("AdoptionPercent = %v, want 0", got.AdoptionPercent)
	}
	if got.CriticalAppsCoverage.Office365 || got.CriticalAppsCoverage.Teams {
		t.Errorf("no app should be covered, got %+v", got.CriticalAppsCoverage)
	}
	// modesByPolicy must list all 3 policies, with p1 missing → "", p2 → disabled, p3 → strictEnforcement.
	if got.ModesByPolicy["p1"] != "" || got.ModesByPolicy["p2"] != types.CAEModeDisabled || got.ModesByPolicy["p3"] != types.CAEModeStrictEnforcement {
		t.Errorf("modesByPolicy unexpected: %+v", got.ModesByPolicy)
	}
}

func TestBuildCAESummary_PartialAdoptionWithResilienceBypass(t *testing.T) {
	// 4 policies, 2 enabled+strict (1 covers Office365 group, 1 only Teams).
	yes := true
	d := &DetectorData{
		AzureConditionalAccessPolicyDetails: []types.ConditionalAccessPolicyDetail{
			mkCAEPolicy("p1", "Strict O365", "enabled", types.CAEModeStrictEnforcement, []string{"Office365"}, nil),
			mkCAEPolicy("p2", "Strict Teams + bypass", "enabled", types.CAEModeStrictEnforcement, []string{"cc15fd57-2c6c-4117-a88c-83b1d56b4bbe"}, &yes),
			mkCAEPolicy("p3", "No CAE", "enabled", "", []string{"All"}, nil),
			mkCAEPolicy("p4", "Disabled mode", "enabled", types.CAEModeDisabled, []string{"All"}, nil),
		},
	}
	got := BuildCAESummary(d, "v3.1.39")
	if !got.Available {
		t.Error("Available should be true")
	}
	if !got.GloballyEnabled {
		t.Error("GloballyEnabled should be true (p1 covers Office365 group)")
	}
	if got.PoliciesWithCAE != 2 {
		t.Errorf("PoliciesWithCAE = %d, want 2", got.PoliciesWithCAE)
	}
	if got.PoliciesEnabledTotal != 4 {
		t.Errorf("PoliciesEnabledTotal = %d, want 4", got.PoliciesEnabledTotal)
	}
	if got.AdoptionPercent != 50.0 {
		t.Errorf("AdoptionPercent = %v, want 50.0", got.AdoptionPercent)
	}
	// p1 covers Office365 group → flips Office365/Exchange/SharePoint/Teams.
	if !got.CriticalAppsCoverage.Office365 || !got.CriticalAppsCoverage.ExchangeOnline ||
		!got.CriticalAppsCoverage.SharePointOnline || !got.CriticalAppsCoverage.Teams {
		t.Errorf("Office365 group should cover all 4, got %+v", got.CriticalAppsCoverage)
	}
	if len(got.ResilienceDefaultsDisabledOnPolicies) != 1 || got.ResilienceDefaultsDisabledOnPolicies[0].ID != "p2" {
		t.Errorf("expected 1 resilience-bypass entry on p2, got %+v", got.ResilienceDefaultsDisabledOnPolicies)
	}
}

func TestBuildCAESummary_TeamsOnlyCoverage(t *testing.T) {
	// Only Teams covered specifically — Office365/Exchange/SharePoint stay false.
	d := &DetectorData{
		AzureConditionalAccessPolicyDetails: []types.ConditionalAccessPolicyDetail{
			mkCAEPolicy("p1", "Teams only", "enabled", types.CAEModeStrictEnforcement, []string{"cc15fd57-2c6c-4117-a88c-83b1d56b4bbe"}, nil),
		},
	}
	got := BuildCAESummary(d, "v3.1.39")
	if got.CriticalAppsCoverage.Teams != true {
		t.Error("Teams should be covered")
	}
	if got.CriticalAppsCoverage.Office365 || got.CriticalAppsCoverage.ExchangeOnline || got.CriticalAppsCoverage.SharePointOnline {
		t.Errorf("only Teams should be covered, got %+v", got.CriticalAppsCoverage)
	}
	if got.GloballyEnabled {
		t.Error("GloballyEnabled should be false (Teams GUID is not All/Office365)")
	}
}

func TestBuildCAESummary_FullAdoption(t *testing.T) {
	// All enabled policies have CAE strict + cover All apps.
	d := &DetectorData{
		AzureConditionalAccessPolicyDetails: []types.ConditionalAccessPolicyDetail{
			mkCAEPolicy("p1", "All apps", "enabled", types.CAEModeStrictEnforcement, []string{"All"}, nil),
			mkCAEPolicy("p2", "All apps 2", "enabled", types.CAEModeStrictEnforcement, []string{"All"}, nil),
		},
	}
	got := BuildCAESummary(d, "v3.1.39")
	if got.AdoptionPercent != 100.0 {
		t.Errorf("AdoptionPercent = %v, want 100", got.AdoptionPercent)
	}
	if !got.GloballyEnabled {
		t.Error("GloballyEnabled should be true")
	}
	if !got.CriticalAppsCoverage.Office365 || !got.CriticalAppsCoverage.Teams {
		t.Error("All apps should cover everything")
	}
}

// Smoke test the schema-fix unmarshal: Microsoft Graph wire format with only
// `mode` (no isEnabled) must derive IsEnabled correctly.
func TestCAEContinuousAccessEvaluation_UnmarshalDerivesIsEnabled(t *testing.T) {
	cases := []struct {
		name        string
		json        string
		wantMode    string
		wantEnabled bool
	}{
		{"strict mode only", `{"mode":"strictEnforcement"}`, "strictEnforcement", true},
		{"disabled mode only", `{"mode":"disabled"}`, "disabled", false},
		{"empty object", `{}`, "", false},
		{"explicit isEnabled wins", `{"isEnabled":true}`, "", true},
		{"explicit isEnabled false with strict mode", `{"mode":"strictEnforcement","isEnabled":false}`, "strictEnforcement", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var got types.CADetailContinuousAccessEvaluation
			if err := got.UnmarshalJSON([]byte(c.json)); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if got.Mode != c.wantMode {
				t.Errorf("Mode = %q, want %q", got.Mode, c.wantMode)
			}
			if got.IsEnabled != c.wantEnabled {
				t.Errorf("IsEnabled = %v, want %v", got.IsEnabled, c.wantEnabled)
			}
		})
	}
}
