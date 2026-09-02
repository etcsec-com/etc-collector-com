// Package audit — License ROI matrix builder (v3.1.38 §1).
//
// Pure post-collection aggregator. Walks the SubscribedSkus + Users + PIM
// + CA policies already on DetectorData (plus 3 best-effort governance
// counts collected upstream) and produces audit.licenseInfo. No Graph
// roundtrip in the helper itself — fully testable.
//
// Powers KPI #12 (License feature ROI) on the SaaS Executive Tab Azure.
// The collector ships data only; the SaaS analyzer derives findings
// (LICENSE_PIM_DORMANT, LICENSE_OVER_PROVISIONING, …).

package audit

import (
	"strings"
	"time"

	"github.com/etcsec-com/etc-collector/pkg/types"
)

// entraServicePlanTier maps a Microsoft service-plan name to the Entra
// license tier it implies. Sources: Microsoft Learn "Product names and
// service plan identifiers for licensing" + EMS / Microsoft 365 SKU bundles.
//
// "p2" implies all P2 features (PIM + Identity Protection + Access Reviews
// + Entitlement Management). "p1" implies the P1 floor (Conditional Access
// available; PIM/IP not).
//
// When Microsoft renames a service plan or adds a new one that bundles
// Entra features, bump this map and ship a new release. Unknown service
// plans are simply ignored — that means the helper might under-count
// licensed users for a feature, never over-count (fail-safe).
var entraServicePlanTier = map[string]string{
	// === Entra ID standalone ===
	"AAD_PREMIUM":              "p1",
	"AAD_PREMIUM_P2":           "p2",
	"AAD_PREMIUM_P2_PIM":       "p2",
	"AAD_BASIC":                "p1",
	"AAD_BASIC_EDU":            "p1",
	"AAD_EDU":                  "p1",
	"IDENTITY_PROTECTION_USER": "p2",
	// === EMS bundles (Enterprise Mobility + Security) ===
	"RMS_S_PREMIUM":  "p1", // EMS E3
	"RMS_S_PREMIUM2": "p2", // EMS E5
	"INTUNE_A":       "p1", // included in EMS bundles
	// === Microsoft 365 / Office 365 bundles that include Entra ===
	"M365_E3_USGOV_GCCHIGH": "p1",
	"M365_E5_USGOV_GCCHIGH": "p2",
	"M365_E3":               "p1",
	"M365_E5":               "p2",
	"M365_F1":               "p1",
	"M365_F3":               "p1",
	"O365_E3":               "p1", // O365 E3 includes AAD_BASIC
	"O365_E5":               "p1", // O365 E5 does NOT include P2 (only EMS E5 / M365 E5 do)
	// === Microsoft 365 Business / Education ===
	"M365_BUSINESS_PREMIUM": "p1",
	"M365_BUSINESS_BASIC":   "", // doesn't include Entra premium
	"M365EDU_A3_FACULTY":    "p1",
	"M365EDU_A5_FACULTY":    "p2",
	"M365EDU_A3_STUDENT":    "p1",
	"M365EDU_A5_STUDENT":    "p2",
	// === Microsoft 365 Frontline (F-SKUs) ===
	"SPE_F1":         "p1",
	"SPE_F5_SECCOMP": "p2", // F5 Security & Compliance add-on
	// === Microsoft 365 E3/E5 SKU IDs (sometimes appear as part numbers) ===
	"SPE_E3": "p1",
	"SPE_E5": "p2",
}

// servicePlanGivesP1 returns true if the named service plan satisfies at
// least the P1 floor (i.e. Conditional Access is available).
func servicePlanGivesP1(name string) bool {
	tier, ok := entraServicePlanTier[strings.ToUpper(name)]
	return ok && (tier == "p1" || tier == "p2")
}

// servicePlanGivesP2 returns true if the named service plan satisfies P2
// (PIM, Identity Protection, Access Reviews, Entitlement Management all
// available).
func servicePlanGivesP2(name string) bool {
	tier, ok := entraServicePlanTier[strings.ToUpper(name)]
	return ok && tier == "p2"
}

// computeP1Coverage returns the total number of licenses across SKUs that
// at least include P1-level Entra capabilities. Used as the headline for
// "Conditional Access licensed seats". Sums prepaidUnits across enabled
// SKUs that have any P1+ service plan.
func computeP1Coverage(skus []types.SubscribedSku) int {
	total := 0
	for _, sku := range skus {
		if !strings.EqualFold(sku.CapabilityStatus, "Enabled") {
			continue
		}
		for _, sp := range sku.ServicePlans {
			if servicePlanGivesP1(sp.ServicePlanName) {
				total += sku.PrepaidUnits
				break
			}
		}
	}
	return total
}

// computeP2Coverage — same as computeP1Coverage but only counts SKUs that
// include a P2-level service plan.
func computeP2Coverage(skus []types.SubscribedSku) int {
	total := 0
	for _, sku := range skus {
		if !strings.EqualFold(sku.CapabilityStatus, "Enabled") {
			continue
		}
		for _, sp := range sku.ServicePlans {
			if servicePlanGivesP2(sp.ServicePlanName) {
				total += sku.PrepaidUnits
				break
			}
		}
	}
	return total
}

// p2SkuIDSet returns the set of skuId values whose SKU includes any
// P2-level service plan. Used for fast user-license filtering.
func p2SkuIDSet(skus []types.SubscribedSku) map[string]struct{} {
	set := make(map[string]struct{}, len(skus))
	for _, sku := range skus {
		if !strings.EqualFold(sku.CapabilityStatus, "Enabled") {
			continue
		}
		for _, sp := range sku.ServicePlans {
			if servicePlanGivesP2(sp.ServicePlanName) {
				set[sku.SkuID] = struct{}{}
				break
			}
		}
	}
	return set
}

// userHasP2 returns true when a user holds at least one SKU from the P2
// set. Cheap lookup — caller pre-builds the set once.
func userHasP2(u *types.User, p2Set map[string]struct{}) bool {
	for _, skuID := range u.AzureAssignedLicenses {
		if _, ok := p2Set[skuID]; ok {
			return true
		}
	}
	return false
}

// countRiskBasedCAPolicies counts CA policies that drive from Identity
// Protection signals (UserRiskLevels or SignInRiskLevels non-empty). A
// non-zero count means the tenant USES Identity Protection.
func countRiskBasedCAPolicies(policies []types.ConditionalAccessPolicy) int {
	count := 0
	for i := range policies {
		p := &policies[i]
		if !strings.EqualFold(p.State, "enabled") {
			continue
		}
		if len(p.UserRiskLevels) > 0 || len(p.SignInRiskLevels) > 0 {
			count++
		}
	}
	return count
}

// countEnabledCAPolicies returns the number of CA policies in state=enabled.
func countEnabledCAPolicies(policies []types.ConditionalAccessPolicy) int {
	count := 0
	for i := range policies {
		if strings.EqualFold(policies[i].State, "enabled") {
			count++
		}
	}
	return count
}

// BuildLicenseInfoSummary aggregates the License ROI payload. governance
// counts come from upstream best-effort calls; pass 0 when the endpoint
// returned 403/404 (Configured stays false / Reason carries why if
// available, but we don't mark dormant=true on uncertain data).
//
// Returns nil for a fully-empty DetectorData (no SKUs, no users, no
// PIM/CA data) so the audit JSON omits audit.licenseInfo entirely on
// trivially-empty tenants. Otherwise returns a populated summary.
func BuildLicenseInfoSummary(
	data *DetectorData,
	accessReviewsCount int,
	accessPackagesCount int,
	verifiedIDIssuersCount int,
	now time.Time,
	version string,
) *types.LicenseInfoSummary {
	if data == nil {
		return nil
	}
	if len(data.AzureSubscribedSkus) == 0 && len(data.Users) == 0 {
		return nil
	}

	p1Cov := computeP1Coverage(data.AzureSubscribedSkus)
	p2Cov := computeP2Coverage(data.AzureSubscribedSkus)

	summary := &types.LicenseInfoSummary{
		SubscribedSkus:   data.AzureSubscribedSkus,
		CollectorVersion: version,
	}

	// === PIM ===
	pim := types.LicenseFeaturePIM{Licensed: p2Cov}
	if data.AzurePIMAssignments != nil {
		pim.Configured = true
		pim.EligibleAssignmentsCount = data.AzurePIMAssignments.Eligible.Total
		pim.ActiveAssignmentsCount = data.AzurePIMAssignments.Active.Total
		if pim.Licensed > 0 && pim.EligibleAssignmentsCount+pim.ActiveAssignmentsCount == 0 {
			pim.Dormant = true
		}
	} else {
		pim.Reason = "PIM data not collected (RoleManagement.Read.Directory or P1/P2 license missing)"
	}
	summary.FeatureUtilization.PIM = pim

	// === Identity Protection ===
	ip := types.LicenseFeatureIdentityProtection{Licensed: p2Cov}
	ip.RiskPoliciesCount = countRiskBasedCAPolicies(data.AzureConditionalAccessPolicies)
	ip.Configured = ip.RiskPoliciesCount > 0
	if ip.Licensed > 0 && ip.RiskPoliciesCount == 0 {
		ip.Dormant = true
	}
	summary.FeatureUtilization.IdentityProtection = ip

	// === Conditional Access ===
	ca := types.LicenseFeatureConditionalAccess{Licensed: p1Cov}
	ca.PoliciesCount = len(data.AzureConditionalAccessPolicies)
	ca.EnabledPoliciesCount = countEnabledCAPolicies(data.AzureConditionalAccessPolicies)
	ca.Configured = ca.PoliciesCount > 0
	if ca.Licensed > 0 && ca.EnabledPoliciesCount == 0 {
		ca.Dormant = true
	}
	summary.FeatureUtilization.ConditionalAccess = ca

	// === Access Reviews ===
	ar := types.LicenseFeatureAccessReviews{
		Licensed:           p2Cov,
		ActiveReviewsCount: accessReviewsCount,
	}
	if accessReviewsCount > 0 {
		ar.Configured = true
	} else if data.AzureAccessReviewsProbed {
		// Probed and got 0 → genuinely dormant.
		if ar.Licensed > 0 {
			ar.Dormant = true
		}
	} else {
		ar.Reason = "Access Reviews endpoint not accessible (AccessReview.Read.All permission required)"
	}
	summary.FeatureUtilization.AccessReviews = ar

	// === Entitlement Management ===
	em := types.LicenseFeatureEntitlementManagement{
		Licensed:            p2Cov,
		AccessPackagesCount: accessPackagesCount,
	}
	if accessPackagesCount > 0 {
		em.Configured = true
	} else if data.AzureAccessPackagesProbed {
		if em.Licensed > 0 {
			em.Dormant = true
		}
	} else {
		em.Reason = "Entitlement Management endpoint not accessible (EntitlementManagement.Read.All permission required)"
	}
	summary.FeatureUtilization.EntitlementManagement = em

	// === Verified ID ===
	vid := types.LicenseFeatureVerifiedID{
		Licensed:     p1Cov, // Verified ID is broadly licensed across M365 SKUs
		IssuersCount: verifiedIDIssuersCount,
	}
	if verifiedIDIssuersCount > 0 {
		vid.Configured = true
	} else if data.AzureVerifiedIDProbed {
		if vid.Licensed > 0 {
			vid.Dormant = true
		}
	} else {
		vid.Reason = "Verified ID endpoint not exposed in Microsoft Graph for this tenant/region"
	}
	summary.FeatureUtilization.VerifiedID = vid

	// === User license distribution ===
	dist := types.LicenseUserDistribution{}
	p2Set := p2SkuIDSet(data.AzureSubscribedSkus)
	cutoff30 := now.AddDate(0, 0, -30)
	cutoff90 := now.AddDate(0, 0, -90)
	for i := range data.Users {
		u := &data.Users[i]
		if len(u.AzureAssignedLicenses) == 0 {
			continue
		}
		dist.TotalLicensedUsers++
		if !userHasP2(u, p2Set) {
			continue
		}
		dist.P2LicensedUsers++
		switch {
		case u.AzureLastSignInDateTime == nil || u.AzureLastSignInDateTime.IsZero():
			dist.P2NeverSignedInUsers++
		case u.AzureLastSignInDateTime.Before(cutoff90):
			dist.P2InactiveUsers90d++
			dist.P2InactiveUsers30d++ // 90-day buckets are also 30-day buckets (subset)
		case u.AzureLastSignInDateTime.Before(cutoff30):
			dist.P2InactiveUsers30d++
		}
	}
	summary.UserLicenseDistribution = dist

	return summary
}
