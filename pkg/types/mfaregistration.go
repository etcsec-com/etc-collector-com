package types

// === v3.1.39 §3 — MFA registration policy + trusted-location restriction ===
//
// On a fresh account or after a password reset, Microsoft Entra prompts the
// user to (re)register MFA factors (Authenticator app, FIDO2 key, phone,
// etc.). If no Conditional Access policy gates that registration flow, an
// attacker who has compromised a password can register their *own* device
// as MFA factor from any IP — bypassing the very protection MFA was meant
// to provide. The Reddit thread `1rfhs1w` documents this attack pattern at
// length (2024-2025).
//
// Microsoft offers a fix: a CA policy targeting the user action
// `urn:user:registersecurityinfo` with a location condition restricted to
// trusted locations. It's not on by default. This summary surfaces whether
// the tenant has it configured so the SaaS analyzer can emit
//   MFA_ENROLLMENT_POLICY_DISABLED        (high)
//   MFA_ENROLLMENT_NO_LOCATION_RESTRICTION (high)
//
// Lands at audit.mfaRegistrationPolicy. Powers KPI #27.

// MFARegistrationPolicySummary is the tenant-wide rollup of CA policies that
// gate the MFA registration flow. Built post-collection — no extra Graph
// roundtrip — by walking the CA policy detail slice and the named locations
// already collected.
type MFARegistrationPolicySummary struct {
	// Available is true when the underlying CA policies detail slice was
	// collected successfully. False when Policy.Read.All scope is missing
	// (Reason populated, all other fields zero).
	Available bool `json:"available"`

	// PoliciesFound counts *enabled* CA policies whose
	// conditions.applications.includeUserActions contains
	// "urn:user:registersecurityinfo". Disabled / report-only policies
	// appear in Policies[] for SaaS visibility but do NOT count here.
	PoliciesFound int `json:"policiesFound"`

	// EnrollmentRestrictedToTrustedLocations is true when at least one
	// of the matched enabled policies has a location condition that
	// resolves to trusted locations only — either via the literal
	// "AllTrusted", or via specific named-location GUIDs all flagged
	// IsTrusted=true. False when no enabled policy restricts at all.
	EnrollmentRestrictedToTrustedLocations bool `json:"enrollmentRestrictedToTrustedLocations"`

	// TrustedLocationCount is the number of NamedLocations on the tenant
	// with IsTrusted=true. Useful context for the SaaS analyzer when
	// reading a "no restriction" finding — distinguishes "no trusted
	// locations defined" from "trusted locations defined but not used".
	TrustedLocationCount int `json:"trustedLocationCount"`

	// RegistrationCampaignEnforced is reserved for a future Graph call to
	// /identityProtection/registrationCampaign. Always false in v3.1.39 —
	// kept in the wire shape so the SaaS analyzer can read both a v3.1.39
	// payload (false) and a future v3.1.40+ payload (real value) without
	// changing its parser.
	RegistrationCampaignEnforced bool `json:"registrationCampaignEnforced"`

	// Policies is the full list of CA policies that target the MFA
	// registration user action, regardless of state. Sorted by DisplayName
	// for deterministic diffs across audits.
	Policies []MFARegistrationPolicyEntry `json:"policies,omitempty"`

	// CollectorVersion is the binary version that built this rollup —
	// lets the SaaS trace a summary back to the exact helper logic.
	CollectorVersion string `json:"collectorVersion"`

	// Reason is populated when Available=false (e.g. Policy.Read.All
	// scope missing). Empty when collection succeeded.
	Reason string `json:"reason,omitempty"`
}

// MFARegistrationPolicyEntry is one CA policy entry surfaced in the rollup,
// along with the boolean derived by the helper indicating whether its
// location condition resolves to trusted locations only.
type MFARegistrationPolicyEntry struct {
	ID                           string   `json:"id"`
	DisplayName                  string   `json:"displayName,omitempty"`
	State                        string   `json:"state"` // enabled | disabled | enabledForReportingButNotEnforced
	UserActions                  []string `json:"userActions"`
	IncludeLocations             []string `json:"includeLocations,omitempty"`
	ExcludeLocations             []string `json:"excludeLocations,omitempty"`
	GrantControls                []string `json:"grantControls,omitempty"`
	RestrictedToTrustedLocations bool     `json:"restrictedToTrustedLocations"`
}
