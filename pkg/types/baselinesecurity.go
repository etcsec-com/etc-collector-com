// Package types — Microsoft Baseline Security Mode adoption (v3.1.37 §1).
//
// Output shape that lands at audit.baselineSecurity in the final payload.
// Built post-collection by audit.BuildBaselineSecuritySummary from
// already-collected DetectorData (Security Defaults, CA policies, auth
// methods detail, authorization policy, admin consent request policy).
//
// No Graph roundtrip in the helper itself — pure derivation. The 20
// baseline policy IDs + descriptions are hardcoded in the binary so an
// audit JSON can be reproduced from the version that emitted it (auditor
// traceability requirement).

package types

// BaselineSecuritySummary is the SaaS-facing rollup. Score is the headline
// adoption % (0-100), counters break it down by status, and Policies[] is
// the per-check detail with evidence + actionable remediation.
type BaselineSecuritySummary struct {
	// Score in [0, 100]. Formula: round((enabled + 0.5*partial) /
	// availablePolicies * 100) where availablePolicies = total - notAvailable
	// - unknown. A tenant Free that activated everything it could reaches 100.
	Score             int `json:"score"`
	TotalPolicies     int `json:"totalPolicies"`
	EnabledCount      int `json:"enabledCount"`
	DisabledCount     int `json:"disabledCount"`
	PartialCount      int `json:"partialCount"`
	UnknownCount      int `json:"unknownCount,omitempty"`
	NotAvailableCount int `json:"notAvailableCount,omitempty"`
	// CollectorVersion is the binary version that emitted this baseline,
	// useful when Microsoft updates the policy list and an auditor needs
	// to know which list was applied. Filled by the helper.
	CollectorVersion string                 `json:"collectorVersion,omitempty"`
	Policies         []BaselinePolicyResult `json:"policies"`
}

// BaselinePolicyResult is one of the ~20 baseline checks. Status follows the
// 5-state convention (enabled | disabled | partial | unknown | not_available).
//
// Evidence is populated for "enabled" / "partial" cases (the policy that
// satisfied the check). Reason is populated on "disabled" / "partial" /
// "unknown" cases (1-line operator-readable explanation). Remediation is
// populated on "disabled" cases (1-line action). Impact is the static
// severity advisory ("high" / "medium" / "low") mapped from the policy
// definition; the SaaS analyzer derives finding severity from this.
type BaselinePolicyResult struct {
	ID          string                  `json:"id"` // BL_BLOCK_LEGACY_AUTH etc.
	Name        string                  `json:"name"`
	Description string                  `json:"description"`
	Status      string                  `json:"status"` // enabled | disabled | partial | unknown | not_available
	Impact      string                  `json:"impact"` // high | medium | low
	Evidence    *BaselinePolicyEvidence `json:"evidence,omitempty"`
	Reason      string                  `json:"reason,omitempty"`
	Remediation string                  `json:"remediation,omitempty"`
}

// BaselinePolicyEvidence points at the upstream object that satisfied (or
// failed) the check, so the SaaS UI can deep-link to the Graph object and
// the auditor can verify the verdict manually.
type BaselinePolicyEvidence struct {
	PolicyType string `json:"policyType,omitempty"` // conditionalAccess | authenticationMethodsPolicy | authorizationPolicy | adminConsentRequestPolicy | securityDefaults | tenantConfig
	PolicyID   string `json:"policyId,omitempty"`
	PolicyName string `json:"policyName,omitempty"`
	Details    string `json:"details,omitempty"`
}
