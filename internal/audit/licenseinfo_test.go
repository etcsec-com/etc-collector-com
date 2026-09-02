package audit

import (
	"testing"
	"time"

	"github.com/etcsec-com/etc-collector/pkg/types"
)

func mkSku(skuID, partNumber, capability string, prepaid, consumed int, planNames ...string) types.SubscribedSku {
	plans := make([]types.SubscribedServicePlan, 0, len(planNames))
	for _, n := range planNames {
		plans = append(plans, types.SubscribedServicePlan{
			ServicePlanID:      "sp-" + n,
			ServicePlanName:    n,
			ProvisioningStatus: "Success",
		})
	}
	avail := prepaid - consumed
	if avail < 0 {
		avail = 0
	}
	return types.SubscribedSku{
		SkuID:            skuID,
		SkuPartNumber:    partNumber,
		CapabilityStatus: capability,
		PrepaidUnits:     prepaid,
		ConsumedUnits:    consumed,
		AvailableUnits:   avail,
		ServicePlans:     plans,
	}
}

func TestComputeP2Coverage_OnlyP2SKUs(t *testing.T) {
	skus := []types.SubscribedSku{
		mkSku("sku1", "AAD_PREMIUM_P2", "Enabled", 100, 80, "AAD_PREMIUM_P2"),
		mkSku("sku2", "AAD_PREMIUM", "Enabled", 50, 30, "AAD_PREMIUM"),
		mkSku("sku3", "POWER_BI_PRO", "Enabled", 20, 10, "BI_AZURE_P2"),
	}
	if got := computeP2Coverage(skus); got != 100 {
		t.Errorf("computeP2Coverage = %d, want 100 (only AAD_PREMIUM_P2 SKU counted)", got)
	}
}

func TestComputeP2Coverage_SuspendedExcluded(t *testing.T) {
	skus := []types.SubscribedSku{
		mkSku("sku1", "AAD_PREMIUM_P2", "Suspended", 100, 0, "AAD_PREMIUM_P2"),
	}
	if got := computeP2Coverage(skus); got != 0 {
		t.Errorf("computeP2Coverage = %d, want 0 (suspended SKU shouldn't count)", got)
	}
}

func TestComputeP1Coverage_IncludesP1AndP2(t *testing.T) {
	// P1 coverage should count BOTH P1-only and P2 SKUs (P2 includes P1).
	skus := []types.SubscribedSku{
		mkSku("sku1", "AAD_PREMIUM", "Enabled", 50, 30, "AAD_PREMIUM"),
		mkSku("sku2", "AAD_PREMIUM_P2", "Enabled", 100, 80, "AAD_PREMIUM_P2"),
	}
	if got := computeP1Coverage(skus); got != 150 {
		t.Errorf("computeP1Coverage = %d, want 150 (both P1 and P2 SKUs)", got)
	}
}

func TestBuildLicenseInfoSummary_NilData(t *testing.T) {
	if got := BuildLicenseInfoSummary(nil, 0, 0, 0, time.Now(), "test"); got != nil {
		t.Errorf("expected nil for nil data, got %+v", got)
	}
}

func TestBuildLicenseInfoSummary_EmptyData_ReturnsNil(t *testing.T) {
	d := &DetectorData{}
	if got := BuildLicenseInfoSummary(d, 0, 0, 0, time.Now(), "test"); got != nil {
		t.Errorf("expected nil for empty data, got %+v", got)
	}
}

func TestBuildLicenseInfoSummary_PIMConfigured_NotDormant(t *testing.T) {
	d := &DetectorData{
		AzureSubscribedSkus: []types.SubscribedSku{
			mkSku("sku-p2", "AAD_PREMIUM_P2", "Enabled", 100, 50, "AAD_PREMIUM_P2"),
		},
		AzurePIMAssignments: &types.PIMAssignmentsSummary{
			Active:   types.PIMActiveSummary{Total: 5},
			Eligible: types.PIMEligibleSummary{Total: 3},
		},
	}
	got := BuildLicenseInfoSummary(d, 0, 0, 0, time.Now(), "test")
	if got == nil {
		t.Fatal("nil summary")
	}
	pim := got.FeatureUtilization.PIM
	if pim.Licensed != 100 {
		t.Errorf("PIM.Licensed = %d, want 100", pim.Licensed)
	}
	if !pim.Configured {
		t.Error("PIM.Configured should be true")
	}
	if pim.EligibleAssignmentsCount != 3 || pim.ActiveAssignmentsCount != 5 {
		t.Errorf("PIM counts = %d/%d, want 3/5", pim.EligibleAssignmentsCount, pim.ActiveAssignmentsCount)
	}
	if pim.Dormant {
		t.Error("PIM.Dormant should be false (3+5 > 0)")
	}
}

func TestBuildLicenseInfoSummary_PIMDormant_LicensedButNotConfigured(t *testing.T) {
	d := &DetectorData{
		AzureSubscribedSkus: []types.SubscribedSku{
			mkSku("sku-p2", "AAD_PREMIUM_P2", "Enabled", 1000, 500, "AAD_PREMIUM_P2"),
		},
		AzurePIMAssignments: &types.PIMAssignmentsSummary{}, // empty totals
	}
	got := BuildLicenseInfoSummary(d, 0, 0, 0, time.Now(), "test")
	pim := got.FeatureUtilization.PIM
	if !pim.Dormant {
		t.Error("PIM.Dormant should be true (P2 licensed, 0 assignments)")
	}
}

func TestBuildLicenseInfoSummary_IdentityProtectionFromCAPolicies(t *testing.T) {
	d := &DetectorData{
		AzureSubscribedSkus: []types.SubscribedSku{
			mkSku("sku-p2", "AAD_PREMIUM_P2", "Enabled", 100, 50, "AAD_PREMIUM_P2"),
		},
		AzureConditionalAccessPolicies: []types.ConditionalAccessPolicy{
			{
				ID:               "ca-risk",
				State:            "enabled",
				SignInRiskLevels: []string{"high"},
				GrantControls:    []string{"block"},
			},
			{
				ID:    "ca-other",
				State: "enabled", // no risk levels
			},
		},
	}
	got := BuildLicenseInfoSummary(d, 0, 0, 0, time.Now(), "test")
	ip := got.FeatureUtilization.IdentityProtection
	if ip.RiskPoliciesCount != 1 {
		t.Errorf("RiskPoliciesCount = %d, want 1", ip.RiskPoliciesCount)
	}
	if !ip.Configured {
		t.Error("IP.Configured should be true")
	}
	if ip.Dormant {
		t.Error("IP.Dormant should be false")
	}
}

func TestBuildLicenseInfoSummary_IdentityProtectionDormant(t *testing.T) {
	d := &DetectorData{
		AzureSubscribedSkus: []types.SubscribedSku{
			mkSku("sku-p2", "AAD_PREMIUM_P2", "Enabled", 100, 50, "AAD_PREMIUM_P2"),
		},
		AzureConditionalAccessPolicies: []types.ConditionalAccessPolicy{
			{ID: "ca-mfa", State: "enabled", GrantControls: []string{"mfa"}}, // no risk levels
		},
	}
	got := BuildLicenseInfoSummary(d, 0, 0, 0, time.Now(), "test")
	if !got.FeatureUtilization.IdentityProtection.Dormant {
		t.Error("IP.Dormant should be true (P2 licensed, 0 risk policies)")
	}
}

func TestBuildLicenseInfoSummary_ConditionalAccessCounters(t *testing.T) {
	d := &DetectorData{
		AzureSubscribedSkus: []types.SubscribedSku{
			mkSku("sku-p1", "AAD_PREMIUM", "Enabled", 200, 150, "AAD_PREMIUM"),
		},
		AzureConditionalAccessPolicies: []types.ConditionalAccessPolicy{
			{ID: "ca1", State: "enabled"},
			{ID: "ca2", State: "enabled"},
			{ID: "ca3", State: "disabled"},
		},
	}
	got := BuildLicenseInfoSummary(d, 0, 0, 0, time.Now(), "test")
	ca := got.FeatureUtilization.ConditionalAccess
	if ca.Licensed != 200 {
		t.Errorf("CA.Licensed = %d, want 200", ca.Licensed)
	}
	if ca.PoliciesCount != 3 {
		t.Errorf("CA.PoliciesCount = %d, want 3", ca.PoliciesCount)
	}
	if ca.EnabledPoliciesCount != 2 {
		t.Errorf("CA.EnabledPoliciesCount = %d, want 2", ca.EnabledPoliciesCount)
	}
}

func TestBuildLicenseInfoSummary_AccessReviewsProbedAndDormant(t *testing.T) {
	d := &DetectorData{
		AzureSubscribedSkus: []types.SubscribedSku{
			mkSku("sku-p2", "AAD_PREMIUM_P2", "Enabled", 100, 50, "AAD_PREMIUM_P2"),
		},
		AzureAccessReviewsProbed: true, // probe ran, returned 0
	}
	got := BuildLicenseInfoSummary(d, 0, 0, 0, time.Now(), "test")
	ar := got.FeatureUtilization.AccessReviews
	if ar.Configured {
		t.Error("AR.Configured should be false (count=0)")
	}
	if !ar.Dormant {
		t.Error("AR.Dormant should be true (P2 licensed, probed, 0 reviews)")
	}
	if ar.Reason != "" {
		t.Errorf("AR.Reason should be empty when probed; got %q", ar.Reason)
	}
}

func TestBuildLicenseInfoSummary_AccessReviewsNotProbed_HasReason(t *testing.T) {
	d := &DetectorData{
		AzureSubscribedSkus: []types.SubscribedSku{
			mkSku("sku-p2", "AAD_PREMIUM_P2", "Enabled", 100, 50, "AAD_PREMIUM_P2"),
		},
		AzureAccessReviewsProbed: false,
	}
	got := BuildLicenseInfoSummary(d, 0, 0, 0, time.Now(), "test")
	ar := got.FeatureUtilization.AccessReviews
	if ar.Dormant {
		t.Error("AR.Dormant should be false when not probed (uncertain)")
	}
	if ar.Reason == "" {
		t.Error("AR.Reason should explain why not probed")
	}
}

func TestBuildLicenseInfoSummary_UserDistribution_BucketsCorrect(t *testing.T) {
	now := time.Date(2026, 5, 7, 12, 0, 0, 0, time.UTC)
	never := (*time.Time)(nil)
	old90 := now.AddDate(0, 0, -100)
	mid40 := now.AddDate(0, 0, -40)
	recent := now.AddDate(0, 0, -5)

	d := &DetectorData{
		AzureSubscribedSkus: []types.SubscribedSku{
			mkSku("sku-p2", "AAD_PREMIUM_P2", "Enabled", 100, 50, "AAD_PREMIUM_P2"),
		},
		Users: []types.User{
			{AzureAssignedLicenses: []string{"sku-p2"}, AzureLastSignInDateTime: never},
			{AzureAssignedLicenses: []string{"sku-p2"}, AzureLastSignInDateTime: &old90},
			{AzureAssignedLicenses: []string{"sku-p2"}, AzureLastSignInDateTime: &mid40},
			{AzureAssignedLicenses: []string{"sku-p2"}, AzureLastSignInDateTime: &recent},
		},
	}
	got := BuildLicenseInfoSummary(d, 0, 0, 0, now, "test")
	dist := got.UserLicenseDistribution
	if dist.TotalLicensedUsers != 4 {
		t.Errorf("TotalLicensedUsers = %d, want 4", dist.TotalLicensedUsers)
	}
	if dist.P2LicensedUsers != 4 {
		t.Errorf("P2LicensedUsers = %d, want 4", dist.P2LicensedUsers)
	}
	if dist.P2NeverSignedInUsers != 1 {
		t.Errorf("P2NeverSignedInUsers = %d, want 1", dist.P2NeverSignedInUsers)
	}
	if dist.P2InactiveUsers90d != 1 {
		t.Errorf("P2InactiveUsers90d = %d, want 1", dist.P2InactiveUsers90d)
	}
	// The 90d-inactive user is also counted in 30d (cumulative bucket).
	if dist.P2InactiveUsers30d != 2 {
		t.Errorf("P2InactiveUsers30d = %d, want 2 (40d + 100d users)", dist.P2InactiveUsers30d)
	}
}

func TestBuildLicenseInfoSummary_NonEntraSKUsAppearInSubscribedSkus(t *testing.T) {
	d := &DetectorData{
		AzureSubscribedSkus: []types.SubscribedSku{
			mkSku("sku1", "POWER_BI_PRO", "Enabled", 50, 40, "BI_AZURE_P2"),
			mkSku("sku2", "VISIOCLIENT", "Enabled", 38, 36, "VISIOONLINE"),
		},
	}
	got := BuildLicenseInfoSummary(d, 0, 0, 0, time.Now(), "test")
	if got == nil {
		t.Fatal("nil — non-Entra SKUs should still produce a summary")
	}
	if len(got.SubscribedSkus) != 2 {
		t.Errorf("SubscribedSkus len = %d, want 2 (no Entra-only filter)", len(got.SubscribedSkus))
	}
	if got.FeatureUtilization.PIM.Licensed != 0 {
		t.Errorf("PIM.Licensed = %d, want 0 (no Entra SKUs)", got.FeatureUtilization.PIM.Licensed)
	}
}
