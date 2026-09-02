package azure

import (
	"encoding/json"
	"testing"

	"github.com/etcsec-com/etc-collector/pkg/types"
)

// Test that the json wire shape coming back from
// /identity/conditionalAccess/policies unmarshals correctly into
// ConditionalAccessPolicyDetail. Three fixtures cover the patterns we expect
// to see in the wild: a fully-populated policy, a partial one (the common
// case where most session controls are null), and a minimal/dormant policy.
//
// The unmarshal path is the single failure mode that matters for v3.1.38 §3
// — if Microsoft adds or renames a field we want the existing fields to keep
// landing where the SaaS analyzer expects them.

const fullPolicyJSON = `{
  "id": "00000000-0000-0000-0000-000000000001",
  "displayName": "Require Token Protection — All Users",
  "state": "enabled",
  "createdDateTime": "2025-01-15T10:00:00Z",
  "modifiedDateTime": "2026-04-01T08:30:00Z",
  "templateId": null,
  "conditions": {
    "applications": {
      "includeApplications": ["All"],
      "excludeApplications": ["00000003-0000-0ff1-ce00-000000000000"],
      "includeUserActions": [],
      "includeAuthenticationContextClassReferences": []
    },
    "users": {
      "includeUsers": ["All"],
      "excludeUsers": ["abc-break-glass"],
      "includeGroups": [],
      "excludeGroups": ["grp-emergency"],
      "includeRoles": [],
      "excludeRoles": [],
      "includeGuestsOrExternalUsers": null,
      "excludeGuestsOrExternalUsers": null
    },
    "clientAppTypes": ["all"],
    "platforms": {
      "includePlatforms": ["windows", "macOS"],
      "excludePlatforms": []
    },
    "locations": null,
    "signInRiskLevels": [],
    "userRiskLevels": [],
    "devices": null,
    "authenticationFlows": null
  },
  "grantControls": {
    "operator": "AND",
    "builtInControls": ["mfa", "compliantDevice"],
    "customAuthenticationFactors": [],
    "termsOfUse": [],
    "authenticationStrength": {
      "id": "00000000-0000-0000-0000-000000000004",
      "displayName": "Phishing-resistant MFA",
      "policyType": "builtIn"
    }
  },
  "sessionControls": {
    "applicationEnforcedRestrictions": null,
    "cloudAppSecurity": null,
    "persistentBrowser": {"isEnabled": true, "mode": "never"},
    "signInFrequency": {"isEnabled": true, "type": "hours", "value": 4, "frequencyInterval": "timeBased", "authenticationType": "primaryAndSecondaryAuthentication"},
    "continuousAccessEvaluation": {"isEnabled": true},
    "secureSignInSession": null,
    "disableResilienceDefaults": false,
    "tokenProtection": {"isEnabled": true}
  }
}`

const partialPolicyJSON = `{
  "id": "00000000-0000-0000-0000-000000000002",
  "displayName": "Block legacy auth",
  "state": "enabled",
  "createdDateTime": "2024-06-01T09:00:00Z",
  "modifiedDateTime": "2024-06-01T09:00:00Z",
  "conditions": {
    "applications": {"includeApplications": ["All"]},
    "users": {"includeUsers": ["All"]},
    "clientAppTypes": ["exchangeActiveSync", "other"]
  },
  "grantControls": {
    "operator": "OR",
    "builtInControls": ["block"]
  },
  "sessionControls": null
}`

const minimalPolicyJSON = `{
  "id": "00000000-0000-0000-0000-000000000003",
  "displayName": "Reporting only — draft",
  "state": "enabledForReportingButNotEnforced"
}`

func TestConditionalAccessPolicyDetail_UnmarshalFull(t *testing.T) {
	var p types.ConditionalAccessPolicyDetail
	if err := json.Unmarshal([]byte(fullPolicyJSON), &p); err != nil {
		t.Fatalf("unmarshal full: %v", err)
	}
	if p.ID != "00000000-0000-0000-0000-000000000001" {
		t.Errorf("ID got %q", p.ID)
	}
	if p.State != "enabled" {
		t.Errorf("State got %q", p.State)
	}
	if p.SessionControls == nil || p.SessionControls.TokenProtection == nil || !p.SessionControls.TokenProtection.IsEnabled {
		t.Error("expected sessionControls.tokenProtection.isEnabled = true")
	}
	if p.SessionControls.SignInFrequency == nil || p.SessionControls.SignInFrequency.Value != 4 || p.SessionControls.SignInFrequency.Type != "hours" {
		t.Errorf("expected signInFrequency 4h, got %+v", p.SessionControls.SignInFrequency)
	}
	if p.SessionControls.PersistentBrowser == nil || !p.SessionControls.PersistentBrowser.IsEnabled || p.SessionControls.PersistentBrowser.Mode != "never" {
		t.Errorf("expected persistentBrowser enabled mode=never, got %+v", p.SessionControls.PersistentBrowser)
	}
	if p.GrantControls == nil || p.GrantControls.AuthenticationStrength == nil || p.GrantControls.AuthenticationStrength.DisplayName != "Phishing-resistant MFA" {
		t.Errorf("expected authStrength populated, got %+v", p.GrantControls)
	}
	if p.Conditions == nil || p.Conditions.Platforms == nil || len(p.Conditions.Platforms.IncludePlatforms) != 2 {
		t.Errorf("expected 2 includePlatforms, got %+v", p.Conditions)
	}
	if p.CreatedDateTime == nil {
		t.Error("expected createdDateTime parsed")
	}
}

func TestConditionalAccessPolicyDetail_UnmarshalPartial(t *testing.T) {
	var p types.ConditionalAccessPolicyDetail
	if err := json.Unmarshal([]byte(partialPolicyJSON), &p); err != nil {
		t.Fatalf("unmarshal partial: %v", err)
	}
	if p.SessionControls != nil {
		t.Errorf("SessionControls should be nil for null literal, got %+v", p.SessionControls)
	}
	if p.GrantControls == nil || p.GrantControls.Operator != "OR" || len(p.GrantControls.BuiltInControls) != 1 || p.GrantControls.BuiltInControls[0] != "block" {
		t.Errorf("expected OR/block grantControls, got %+v", p.GrantControls)
	}
	if p.Conditions == nil || len(p.Conditions.ClientAppTypes) != 2 {
		t.Errorf("expected 2 clientAppTypes, got %+v", p.Conditions)
	}
}

func TestConditionalAccessPolicyDetail_UnmarshalMinimal(t *testing.T) {
	var p types.ConditionalAccessPolicyDetail
	if err := json.Unmarshal([]byte(minimalPolicyJSON), &p); err != nil {
		t.Fatalf("unmarshal minimal: %v", err)
	}
	if p.State != "enabledForReportingButNotEnforced" {
		t.Errorf("State got %q", p.State)
	}
	if p.Conditions != nil || p.GrantControls != nil || p.SessionControls != nil {
		t.Error("nested blocks should be nil when absent")
	}
}

// Sanity check: the full Graph response wrapper {value: [...]} round-trips.
func TestConditionalAccessPoliciesDetail_PageWrapper(t *testing.T) {
	body := []byte(`{"value":[` + fullPolicyJSON + `,` + partialPolicyJSON + `,` + minimalPolicyJSON + `]}`)
	var page struct {
		Value []types.ConditionalAccessPolicyDetail `json:"value"`
	}
	if err := json.Unmarshal(body, &page); err != nil {
		t.Fatalf("unmarshal page: %v", err)
	}
	if len(page.Value) != 3 {
		t.Fatalf("expected 3 policies, got %d", len(page.Value))
	}
	if page.Value[0].SessionControls == nil || !page.Value[0].SessionControls.TokenProtection.IsEnabled {
		t.Error("first policy lost tokenProtection on page unmarshal")
	}
}
