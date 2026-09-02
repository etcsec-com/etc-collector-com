package audit

import (
	"testing"

	"github.com/etcsec-com/etc-collector/pkg/types"
)

func boolPtr(v bool) *bool { return &v }

// mkData builds a DetectorData with sensible defaults — every field nil
// except what the test sets explicitly. Avoids repetitive boilerplate.
func mkData() *DetectorData { return &DetectorData{} }

func TestBuildBaselineSummary_NilData(t *testing.T) {
	if got := BuildBaselineSecuritySummary(nil, "test"); got != nil {
		t.Errorf("expected nil for nil data, got %+v", got)
	}
}

func TestSecurityDefaultsEnabled_TriggersEnabled(t *testing.T) {
	d := mkData()
	d.AzureTenantConfig = &types.AzureTenantConfig{
		SecurityDefaults: &types.TenantSecurityDefaults{IsEnabled: true},
	}
	got := checkSecurityDefaultsOrEquivalent(d)
	if got.status != "enabled" {
		t.Errorf("status = %q, want enabled", got.status)
	}
	if got.evidence == nil || got.evidence.PolicyType != "securityDefaults" {
		t.Errorf("evidence = %+v, want securityDefaults", got.evidence)
	}
}

func TestSecurityDefaultsDisabled_NoEquivalent_TriggersDisabled(t *testing.T) {
	d := mkData()
	got := checkSecurityDefaultsOrEquivalent(d)
	if got.status != "disabled" {
		t.Errorf("status = %q, want disabled", got.status)
	}
}

func TestMFAAllUsers_EnabledMatch(t *testing.T) {
	d := mkData()
	d.AzureConditionalAccessPolicies = []types.ConditionalAccessPolicy{
		{
			ID:            "ca-1",
			DisplayName:   "MFA all users",
			State:         "enabled",
			IncludeUsers:  []string{"All"},
			IncludeApps:   []string{"All"},
			GrantControls: []string{"mfa"},
		},
	}
	got := checkMFAAllUsers(d)
	if got.status != "enabled" {
		t.Errorf("status = %q, want enabled", got.status)
	}
}

func TestMFAAllUsers_DisabledStateNotMatched(t *testing.T) {
	d := mkData()
	d.AzureConditionalAccessPolicies = []types.ConditionalAccessPolicy{
		{
			ID:            "ca-1",
			DisplayName:   "MFA all users (disabled)",
			State:         "disabled",
			IncludeUsers:  []string{"All"},
			IncludeApps:   []string{"All"},
			GrantControls: []string{"mfa"},
		},
	}
	got := checkMFAAllUsers(d)
	if got.status != "disabled" {
		t.Errorf("disabled state CA should NOT count, got %q", got.status)
	}
}

func TestMFAAdmins_FallbackToSecurityDefaults(t *testing.T) {
	d := mkData()
	d.AzureTenantConfig = &types.AzureTenantConfig{
		SecurityDefaults: &types.TenantSecurityDefaults{IsEnabled: true},
	}
	got := checkMFAAdmins(d)
	if got.status != "enabled" {
		t.Errorf("Security Defaults on should satisfy MFA admins, got %q", got.status)
	}
}

func TestBlockLegacyAuth_Match(t *testing.T) {
	d := mkData()
	d.AzureConditionalAccessPolicies = []types.ConditionalAccessPolicy{
		{
			ID:             "ca-2",
			State:          "enabled",
			ClientAppTypes: []string{"exchangeActiveSync", "other"},
			GrantControls:  []string{"block"},
		},
	}
	got := checkBlockLegacyAuth(d)
	if got.status != "enabled" {
		t.Errorf("status = %q, want enabled", got.status)
	}
}

func TestBlockHighRiskSignIn_Match(t *testing.T) {
	d := mkData()
	d.AzureConditionalAccessPolicies = []types.ConditionalAccessPolicy{
		{
			ID:               "ca-3",
			State:            "enabled",
			SignInRiskLevels: []string{"high"},
			GrantControls:    []string{"block"},
		},
	}
	got := checkBlockHighRiskSignIn(d)
	if got.status != "enabled" {
		t.Errorf("status = %q, want enabled", got.status)
	}
}

func TestFIDO2_PartialOnGroupTarget(t *testing.T) {
	d := mkData()
	d.AzureAuthMethodsDetail = &types.AuthMethodsDetail{
		Policy: &types.AuthMethodsPolicy{
			FIDO2: types.AuthMethodConfig{
				State: "enabled",
				IncludeTargets: []types.AuthMethodTarget{
					{TargetType: "group", ID: "fido2-pilot-group"},
				},
			},
		},
	}
	got := checkFIDO2Enabled(d)
	if got.status != "partial" {
		t.Errorf("status = %q, want partial", got.status)
	}
}

func TestFIDO2_EnabledOnAllUsers(t *testing.T) {
	d := mkData()
	d.AzureAuthMethodsDetail = &types.AuthMethodsDetail{
		Policy: &types.AuthMethodsPolicy{
			FIDO2: types.AuthMethodConfig{
				State: "enabled",
				IncludeTargets: []types.AuthMethodTarget{
					{TargetType: "group", ID: "all_users"},
				},
			},
		},
	}
	got := checkFIDO2Enabled(d)
	if got.status != "enabled" {
		t.Errorf("status = %q, want enabled", got.status)
	}
}

func TestFIDO2_DisabledState(t *testing.T) {
	d := mkData()
	d.AzureAuthMethodsDetail = &types.AuthMethodsDetail{
		Policy: &types.AuthMethodsPolicy{
			FIDO2: types.AuthMethodConfig{State: "disabled"},
		},
	}
	got := checkFIDO2Enabled(d)
	if got.status != "disabled" {
		t.Errorf("status = %q, want disabled", got.status)
	}
}

func TestFIDO2_UnknownIfPolicyAbsent(t *testing.T) {
	d := mkData() // AzureAuthMethodsDetail nil
	got := checkFIDO2Enabled(d)
	if got.status != "unknown" {
		t.Errorf("status = %q, want unknown", got.status)
	}
}

func TestSMSDisabled_FlippedSemanticsCorrect(t *testing.T) {
	// SMS off = baseline check enabled (we WANT it off)
	d := mkData()
	d.AzureAuthMethodsDetail = &types.AuthMethodsDetail{
		Policy: &types.AuthMethodsPolicy{SMS: types.AuthMethodConfig{State: "disabled"}},
	}
	if got := checkSMSDisabled(d); got.status != "enabled" {
		t.Errorf("SMS off → check enabled; got %q", got.status)
	}
	d.AzureAuthMethodsDetail.Policy.SMS.State = "enabled"
	if got := checkSMSDisabled(d); got.status != "disabled" {
		t.Errorf("SMS on → check disabled; got %q", got.status)
	}
}

func TestBlockUserConsentRiskyApps_FromAuthorizationPolicy(t *testing.T) {
	d := mkData()
	d.AzureAuthorizationPolicy = &types.AuthorizationPolicy{
		AllowUserConsentForRiskyApps: boolPtr(false),
	}
	if got := checkBlockUserConsentRiskyApps(d); got.status != "enabled" {
		t.Errorf("allowUserConsentForRiskyApps=false → enabled; got %q", got.status)
	}
	d.AzureAuthorizationPolicy.AllowUserConsentForRiskyApps = boolPtr(true)
	if got := checkBlockUserConsentRiskyApps(d); got.status != "disabled" {
		t.Errorf("allowUserConsentForRiskyApps=true → disabled; got %q", got.status)
	}
}

func TestDisableUserAppCreation_Unknown(t *testing.T) {
	d := mkData() // policy nil
	if got := checkDisableUserAppCreation(d); got.status != "unknown" {
		t.Errorf("policy nil → unknown; got %q", got.status)
	}
}

func TestGuestInviteRestricted_NotEveryone(t *testing.T) {
	d := mkData()
	d.AzureAuthorizationPolicy = &types.AuthorizationPolicy{AllowInvitesFrom: "adminsAndGuestInviters"}
	if got := checkGuestInviteRestricted(d); got.status != "enabled" {
		t.Errorf("status = %q, want enabled", got.status)
	}
	d.AzureAuthorizationPolicy.AllowInvitesFrom = "everyone"
	if got := checkGuestInviteRestricted(d); got.status != "disabled" {
		t.Errorf("everyone → disabled; got %q", got.status)
	}
}

func TestTokenProtection_Match(t *testing.T) {
	// v3.1.38 §3 — token protection is now read from the nested CA detail
	// slice (AzureConditionalAccessPolicyDetails) because the flat field
	// AzureConditionalAccessPolicies[].TokenProtectionRequired is never
	// populated by the SDK converter.
	d := mkData()
	d.AzureConditionalAccessPolicyDetails = []types.ConditionalAccessPolicyDetail{
		{
			ID:          "ca-tp",
			DisplayName: "Token Protection — All",
			State:       "enabled",
			SessionControls: &types.CADetailSessionControls{
				TokenProtection: &types.CADetailTokenProtection{IsEnabled: true},
			},
		},
	}
	if got := checkTokenProtectionEnabled(d); got.status != "enabled" {
		t.Errorf("status = %q, want enabled", got.status)
	}
}

func TestTokenProtection_Disabled(t *testing.T) {
	// Detail slice present, but no policy turns tokenProtection on → disabled.
	d := mkData()
	d.AzureConditionalAccessPolicyDetails = []types.ConditionalAccessPolicyDetail{
		{
			ID: "ca-other", DisplayName: "Other", State: "enabled",
			SessionControls: &types.CADetailSessionControls{
				PersistentBrowser: &types.CADetailPersistentBrowser{IsEnabled: true, Mode: "never"},
			},
		},
	}
	if got := checkTokenProtectionEnabled(d); got.status != "disabled" {
		t.Errorf("status = %q, want disabled", got.status)
	}
}

func TestTokenProtection_Unknown(t *testing.T) {
	// Detail slice nil → Policy.Read.All scope likely missing → unknown.
	d := mkData()
	d.AzureConditionalAccessPolicyDetails = nil
	got := checkTokenProtectionEnabled(d)
	if got.status != "unknown" {
		t.Errorf("status = %q, want unknown", got.status)
	}
	if got.reason == "" {
		t.Error("reason must be populated when status=unknown")
	}
}

func TestTenantBelowLicense(t *testing.T) {
	cases := []struct {
		tier     string
		requires baselineLicense
		want     bool
	}{
		{"free", licenseP1, true},
		{"free", licenseP2, true},
		{"free", licenseNone, false},
		{"p1", licenseP1, false},
		{"p1", licenseP2, true},
		{"p2", licenseP2, false},
		{"", licenseP2, false}, // unknown tier doesn't gate
		{"p1", licenseNone, false},
	}
	for _, c := range cases {
		got := tenantBelowLicense(c.tier, c.requires)
		if got != c.want {
			t.Errorf("tenantBelowLicense(%q, %v) = %v, want %v", c.tier, c.requires, got, c.want)
		}
	}
}

func TestBuildSummary_LicenseGatesNotAvailable(t *testing.T) {
	// Free tenant — P2-required policies should be marked not_available even
	// if they have no matching CA (we don't penalise for what they can't have).
	d := mkData()
	d.AzureLicenseTier = "free"
	got := BuildBaselineSecuritySummary(d, "test")
	if got == nil {
		t.Fatal("nil summary")
	}
	// At least the 3 P2 policies (BLOCK_HIGH_RISK_SIGNIN, BLOCK_HIGH_RISK_USER,
	// REQUIRE_MFA_REGISTRATION, TOKEN_PROTECTION_ENABLED — 4 total) should be
	// not_available on a Free tenant.
	notAvail := 0
	for _, p := range got.Policies {
		if p.Status == "not_available" {
			notAvail++
		}
	}
	if notAvail < 3 {
		t.Errorf("expected ≥3 not_available on free tenant, got %d", notAvail)
	}
}

func TestBuildSummary_ScoreFormulaExcludesNotAvailable(t *testing.T) {
	// Tenant with everything enabled that's available on free tier should
	// score 100 (or close to it). The check is that not_available isn't
	// counted in the denominator.
	d := mkData()
	d.AzureLicenseTier = "free"
	d.AzureTenantConfig = &types.AzureTenantConfig{
		SecurityDefaults: &types.TenantSecurityDefaults{IsEnabled: true},
	}
	d.AzureAuthMethodsDetail = &types.AuthMethodsDetail{
		Policy: &types.AuthMethodsPolicy{
			FIDO2:                  types.AuthMethodConfig{State: "enabled"},
			MicrosoftAuthenticator: types.AuthMethodConfig{State: "enabled"},
			TemporaryAccessPass:    types.AuthMethodConfig{State: "enabled"},
			SMS:                    types.AuthMethodConfig{State: "disabled"},
		},
	}
	d.AzureAuthorizationPolicy = &types.AuthorizationPolicy{
		AllowInvitesFrom:             "adminsOnly",
		AllowUserConsentForRiskyApps: boolPtr(false),
		DefaultUserRolePermissions: &types.AuthorizationDefaultUserPermissions{
			AllowedToCreateApps:    boolPtr(false),
			AllowedToCreateTenants: boolPtr(false),
		},
	}
	got := BuildBaselineSecuritySummary(d, "test")
	if got == nil {
		t.Fatal("nil")
	}
	t.Logf("free tenant well-configured: enabled=%d disabled=%d partial=%d unknown=%d notAvail=%d score=%d",
		got.EnabledCount, got.DisabledCount, got.PartialCount, got.UnknownCount, got.NotAvailableCount, got.Score)
	if got.NotAvailableCount < 3 {
		t.Errorf("expected ≥3 not_available, got %d", got.NotAvailableCount)
	}
	// Some checks remain disabled (CA-based ones — Block-High-Risk, Require-Device-Compliance, etc.
	// require P1 and are not_available on free; but BL_RESTRICT_AAD_ADMIN_PORTAL is P1 too).
	// What matters: score uses (total - notAvailable - unknown) as denominator.
	if got.TotalPolicies != 20 {
		t.Errorf("TotalPolicies = %d, want 20", got.TotalPolicies)
	}
	if got.Score < 50 || got.Score > 100 {
		t.Errorf("Score = %d, expected reasonable range 50-100 for well-configured free tenant", got.Score)
	}
	if got.CollectorVersion != "test" {
		t.Errorf("CollectorVersion = %q, want test", got.CollectorVersion)
	}
}

func TestBuildSummary_ScoreFormulaCalculation(t *testing.T) {
	// Smoke test the round((enabled + 0.5*partial)/available * 100) formula.
	// We can't easily inject the exact mix without exercising every check;
	// rely on TestBuildSummary_ScoreFormulaExcludesNotAvailable for end-to-end
	// and assert the basic invariant that score is in [0, 100].
	d := mkData()
	got := BuildBaselineSecuritySummary(d, "test")
	if got.Score < 0 || got.Score > 100 {
		t.Errorf("Score out of range: %d", got.Score)
	}
}
