package types

// === v3.1.39 §1 — Continuous Access Evaluation (CAE) tenant aggregate ===
//
// CAE allows near-instant token revocation in Microsoft Entra (instead of
// waiting ~1h for default token expiry). Without CAE, a disabled user
// retains valid tokens for up to ~1h — a major risk on admin accounts.
//
// The per-policy CAE flag is already exposed on
// audit.conditionalAccessPolicies[].sessionControls.continuousAccessEvaluation
// (delivered v3.1.38 §3, with the v3.1.39 §1 schema fix that finally captures
// the `mode` enum). This summary rolls those flags up into a tenant-wide
// view so the SaaS analyzer can render the CAE Coverage Card and emit
// CAE_NOT_GLOBALLY_ENABLED / CAE_RESILIENCE_BYPASS_ALLOWED /
// CAE_CRITICAL_APPS_NOT_COVERED findings.
//
// Lands at audit.cae. Powers KPI #23.

// CAESummary is the tenant-wide rollup of Continuous Access Evaluation
// adoption, derived post-collection from the CA policies detail slice.
type CAESummary struct {
	// Available is true when the underlying CA policies detail slice was
	// collected successfully. False when Policy.Read.All scope is missing
	// (in that case Reason is populated and all other fields are zero).
	Available bool `json:"available"`

	// GloballyEnabled is a heuristic: true when at least one enabled CA
	// policy enforces CAE in strictEnforcement mode AND targets either
	// "All" applications or the "Office365" group identifier. The SaaS
	// analyzer can apply a stricter threshold if needed.
	GloballyEnabled bool `json:"globallyEnabled"`

	// PoliciesWithCAE is the count of *enabled* CA policies that have
	// continuousAccessEvaluation.mode == "strictEnforcement".
	PoliciesWithCAE int `json:"policiesWithCae"`

	// PoliciesEnabledTotal is the count of enabled CA policies. Used as
	// the denominator for AdoptionPercent.
	PoliciesEnabledTotal int `json:"policiesEnabledTotal"`

	// PoliciesTotal is the total count of CA policies (enabled + disabled
	// + reportOnly). Mirror of len(audit.conditionalAccessPolicies).
	PoliciesTotal int `json:"policiesTotal"`

	// AdoptionPercent = PoliciesWithCAE / PoliciesEnabledTotal * 100,
	// rounded to one decimal. Zero when the denominator is zero.
	AdoptionPercent float64 `json:"adoptionPercent"`

	// ModesByPolicy maps every CA policy ID to its CAE mode string
	// (strictEnforcement | disabled | "" when the control is absent).
	// Helps the SaaS surface per-policy state in the coverage matrix.
	ModesByPolicy map[string]string `json:"modesByPolicy,omitempty"`

	// ResilienceDefaultsDisabledOnPolicies lists every enabled policy
	// where sessionControls.disableResilienceDefaults == true. Each
	// entry powers the CAE_RESILIENCE_BYPASS_ALLOWED finding.
	ResilienceDefaultsDisabledOnPolicies []CAEPolicyRef `json:"resilienceDefaultsDisabledOnPolicies,omitempty"`

	// CriticalAppsCoverage tells whether each of the 4 critical Microsoft
	// 365 apps is covered by at least one enabled CA policy with CAE in
	// strictEnforcement mode. Powers CAE_CRITICAL_APPS_NOT_COVERED.
	CriticalAppsCoverage CAECriticalAppsCoverage `json:"criticalAppsCoverage"`

	// CollectorVersion is the binary version that built this rollup —
	// lets the SaaS trace a CAE summary back to the exact helper logic.
	CollectorVersion string `json:"collectorVersion"`

	// Reason is populated when Available=false (e.g. Policy.Read.All
	// scope missing). Empty when collection succeeded.
	Reason string `json:"reason,omitempty"`
}

// CAEPolicyRef is a lightweight reference to a CA policy, used in the
// resilience-bypass list. We keep it minimal because the full policy is
// already in audit.conditionalAccessPolicies.
type CAEPolicyRef struct {
	ID          string `json:"id"`
	DisplayName string `json:"displayName,omitempty"`
}

// CAECriticalAppsCoverage carries the per-app coverage flags for the four
// Microsoft 365 apps the SaaS analyzer treats as "must be covered".
type CAECriticalAppsCoverage struct {
	Office365        bool `json:"office365"`
	ExchangeOnline   bool `json:"exchangeOnline"`
	SharePointOnline bool `json:"sharePointOnline"`
	Teams            bool `json:"teams"`
}
