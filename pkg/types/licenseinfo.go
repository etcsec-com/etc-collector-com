// Package types — Microsoft 365 / Entra ID license info detail (v3.1.38 §1).
//
// Lands at audit.licenseInfo. Powers the SaaS License ROI Matrix
// (Executive Tab Azure / KPI #12) — answer to "which paid Entra features
// are activated vs dormant?" so the CFO can see the wasted spend
// (~$9/user/month for Entra ID P2 — 1000 dormant licenses = $108k/yr).
//
// The collector ships only data — no findings. The SaaS analyzer derives
// LICENSE_PIM_DORMANT (critical), LICENSE_IDENTITY_PROTECTION_DORMANT
// (high), LICENSE_ACCESS_REVIEWS_DORMANT (medium),
// LICENSE_OVER_PROVISIONING (high when >20% P2 users inactive 90d).

package types

// LicenseInfoSummary is the SaaS-facing rollup. Three tiers of detail:
//   - subscribedSkus[]: raw list of every SKU the tenant pays for
//     (Entra-related + non-Entra like Power BI, Visio — caller decides
//     what to display)
//   - featureUtilization: per-feature Entra-specific quadruplet
//     (licensed × configured × counts × dormant) for the 6 features
//     called out in the ROI matrix
//   - userLicenseDistribution: P2-licensed user activity buckets so the
//     analyzer can compute LICENSE_OVER_PROVISIONING
type LicenseInfoSummary struct {
	SubscribedSkus          []SubscribedSku           `json:"subscribedSkus"`
	FeatureUtilization      LicenseFeatureUtilization `json:"featureUtilization"`
	UserLicenseDistribution LicenseUserDistribution   `json:"userLicenseDistribution"`

	// CollectorVersion is embedded so an audit JSON traces back to the
	// binary version that emitted the verdict (the entraServicePlanTier
	// table evolves as Microsoft adds SKUs).
	CollectorVersion string `json:"collectorVersion,omitempty"`
}

// SubscribedSku mirrors a /subscribedSkus entry. We surface enough fields
// for the ROI matrix UI: SKU identity (skuId / skuPartNumber), capacity
// (prepaidUnits / consumedUnits / availableUnits), capability state, and
// the embedded servicePlans list for fine-grained "which features are
// active in this SKU" rendering.
type SubscribedSku struct {
	SkuID            string                  `json:"skuId"`
	SkuPartNumber    string                  `json:"skuPartNumber"`
	DisplayName      string                  `json:"displayName,omitempty"`
	CapabilityStatus string                  `json:"capabilityStatus,omitempty"` // Enabled | Suspended | Warning
	PrepaidUnits     int                     `json:"prepaidUnits"`
	ConsumedUnits    int                     `json:"consumedUnits"`
	AvailableUnits   int                     `json:"availableUnits"`
	ServicePlans     []SubscribedServicePlan `json:"servicePlans,omitempty"`
}

// SubscribedServicePlan is one entry from a SKU's servicePlans array.
type SubscribedServicePlan struct {
	ServicePlanID      string `json:"servicePlanId"`
	ServicePlanName    string `json:"servicePlanName"`
	ProvisioningStatus string `json:"provisioningStatus,omitempty"` // Success | Disabled | Pending | etc.
}

// LicenseFeatureUtilization carries the per-feature ROI fields. For each
// feature, we report licensed (the count of users covered by a SKU that
// includes this feature), configured (whether the feature has any
// configured object on this tenant), counts that justify the
// configured flag, and dormant (licensed > 0 && nothing configured).
//
// Reason is populated when configured is uncertain — typically because
// the upstream Graph endpoint returned 403/404 and we can't observe the
// configured state. The SaaS analyzer should NOT flag dormant in that
// case; it should surface the Reason instead.
type LicenseFeatureUtilization struct {
	PIM                   LicenseFeaturePIM                   `json:"pim"`
	IdentityProtection    LicenseFeatureIdentityProtection    `json:"identityProtection"`
	ConditionalAccess     LicenseFeatureConditionalAccess     `json:"conditionalAccess"`
	AccessReviews         LicenseFeatureAccessReviews         `json:"accessReviews"`
	EntitlementManagement LicenseFeatureEntitlementManagement `json:"entitlementManagement"`
	VerifiedID            LicenseFeatureVerifiedID            `json:"verifiedId"`
}

// LicenseFeaturePIM — Privileged Identity Management. Counts come from
// data.AzurePIMAssignments (already collected v3.1.30 §4).
type LicenseFeaturePIM struct {
	Licensed                 int    `json:"licensed"`
	Configured               bool   `json:"configured"`
	EligibleAssignmentsCount int    `json:"eligibleAssignmentsCount"`
	ActiveAssignmentsCount   int    `json:"activeAssignmentsCount"`
	Dormant                  bool   `json:"dormant"`
	Reason                   string `json:"reason,omitempty"`
}

// LicenseFeatureIdentityProtection — Identity Protection risk policies.
// Detected from CA policies whose Conditions.UserRiskLevels or
// SignInRiskLevels are non-empty (those are the policies driving from
// Identity Protection signals).
type LicenseFeatureIdentityProtection struct {
	Licensed          int    `json:"licensed"`
	Configured        bool   `json:"configured"`
	RiskPoliciesCount int    `json:"riskPoliciesCount"`
	Dormant           bool   `json:"dormant"`
	Reason            string `json:"reason,omitempty"`
}

// LicenseFeatureConditionalAccess — counters straight from
// data.AzureConditionalAccessPolicies. CA is included in P1 and P2, so
// most M365 SKUs include it.
type LicenseFeatureConditionalAccess struct {
	Licensed             int    `json:"licensed"`
	Configured           bool   `json:"configured"`
	PoliciesCount        int    `json:"policiesCount"`
	EnabledPoliciesCount int    `json:"enabledPoliciesCount"`
	Dormant              bool   `json:"dormant"`
	Reason               string `json:"reason,omitempty"`
}

// LicenseFeatureAccessReviews — count from
// /identityGovernance/accessReviews/definitions (best-effort, single-shot).
// On 403 (perm AccessReview.Read.All missing), Reason carries the
// diagnostic and Configured/Dormant are conservatively set to false/false
// (we can't confirm dormancy without the endpoint).
type LicenseFeatureAccessReviews struct {
	Licensed           int    `json:"licensed"`
	Configured         bool   `json:"configured"`
	ActiveReviewsCount int    `json:"activeReviewsCount"`
	Dormant            bool   `json:"dormant"`
	Reason             string `json:"reason,omitempty"`
}

// LicenseFeatureEntitlementManagement — count from
// /identityGovernance/entitlementManagement/accessPackages.
type LicenseFeatureEntitlementManagement struct {
	Licensed            int    `json:"licensed"`
	Configured          bool   `json:"configured"`
	AccessPackagesCount int    `json:"accessPackagesCount"`
	Dormant             bool   `json:"dormant"`
	Reason              string `json:"reason,omitempty"`
}

// LicenseFeatureVerifiedID — count from /verifiableCredentials/authorities.
// On many tenants this segment isn't even exposed in Graph yet (HTTP 400).
type LicenseFeatureVerifiedID struct {
	Licensed          int    `json:"licensed"`
	Configured        bool   `json:"configured"`
	IssuersCount      int    `json:"issuersCount"`
	CredentialsIssued int    `json:"credentialsIssued"` // not currently fetched — placeholder for v3.1.39+
	Dormant           bool   `json:"dormant"`
	Reason            string `json:"reason,omitempty"`
}

// LicenseUserDistribution captures the activity profile of P2-licensed
// users — the data the SaaS analyzer needs to detect over-provisioning
// (e.g. >20% of P2 users haven't signed in for 90 days = wasted spend).
type LicenseUserDistribution struct {
	TotalLicensedUsers   int `json:"totalLicensedUsers"`   // any SKU
	P2LicensedUsers      int `json:"p2LicensedUsers"`      // users with at least one P2 SKU
	P2InactiveUsers30d   int `json:"p2InactiveUsers30d"`   // P2 users with last sign-in > 30d ago
	P2InactiveUsers90d   int `json:"p2InactiveUsers90d"`   // P2 users with last sign-in > 90d ago
	P2NeverSignedInUsers int `json:"p2NeverSignedInUsers"` // P2 users with nil/zero LastSignInDateTime
}
