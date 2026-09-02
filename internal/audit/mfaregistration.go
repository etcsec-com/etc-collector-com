// Package audit — MFA registration policy rollup builder (v3.1.39 §3).
//
// Pure post-collection aggregator. Walks data.AzureConditionalAccessPolicyDetails
// (already collected in v3.1.38 §3) cross-referenced with data.AzureNamedLocations
// to determine whether the tenant has CA policies that gate the MFA
// registration flow (userActions = urn:user:registersecurityinfo) and
// whether those policies restrict enrollment to trusted locations.
//
// No additional Graph roundtrip — this is a pure derivation helper.
//
// The SaaS analyzer consumes audit.mfaRegistrationPolicy to emit:
//   MFA_ENROLLMENT_POLICY_DISABLED         (no enabled policy targets the action)
//   MFA_ENROLLMENT_NO_LOCATION_RESTRICTION (policy(s) found but no trusted-location restriction)

package audit

import (
	"sort"

	"github.com/etcsec-com/etc-collector/pkg/types"
)

// mfaRegistrationUserAction is the Microsoft-defined sentinel string used in
// CA policy `conditions.applications.includeUserActions` to target the MFA /
// security-info registration flow. Public and stable since the feature was
// introduced in 2018.
const mfaRegistrationUserAction = "urn:user:registersecurityinfo"

// CA location-condition sentinels. "AllTrusted" is the canonical way to say
// "any location flagged isTrusted=true on this tenant" without listing
// individual GUIDs. "All" means "any IP whatsoever" — the opposite signal.
const (
	caLocationAllTrusted = "AllTrusted"
	caLocationAll        = "All"
)

// BuildMFARegistrationPolicySummary derives the MFA-enrollment CA policy
// rollup from the CA policies detail slice + named locations. Returns nil
// only when data is nil. When the CA detail slice is missing (Policy.Read.All
// scope denied), returns Available=false with a Reason.
func BuildMFARegistrationPolicySummary(data *DetectorData, version string) *types.MFARegistrationPolicySummary {
	if data == nil {
		return nil
	}

	summary := &types.MFARegistrationPolicySummary{
		CollectorVersion: version,
	}

	// Count trusted locations and build a lookup map from GUID → trusted.
	// Useful for both the top-level TrustedLocationCount counter and for
	// resolving policy-level IncludeLocations entries.
	trustedByID := make(map[string]bool, len(data.AzureNamedLocations))
	for i := range data.AzureNamedLocations {
		nl := &data.AzureNamedLocations[i]
		trustedByID[nl.ID] = nl.IsTrusted
		if nl.IsTrusted {
			summary.TrustedLocationCount++
		}
	}

	if data.AzureConditionalAccessPolicyDetails == nil {
		summary.Available = false
		summary.Reason = "Conditional Access policy detail not collected (Policy.Read.All scope likely missing)."
		return summary
	}
	summary.Available = true

	// Walk every CA policy. We surface ALL policies (regardless of state)
	// that target the MFA registration user action, so the SaaS analyzer
	// can show disabled / report-only policies in the UI. Only enabled
	// policies count toward PoliciesFound and the top-level restriction
	// flag.
	for i := range data.AzureConditionalAccessPolicyDetails {
		p := &data.AzureConditionalAccessPolicyDetails[i]
		if !targetsMFARegistration(p) {
			continue
		}
		entry := buildMFARegistrationEntry(p, trustedByID)
		summary.Policies = append(summary.Policies, entry)

		if p.State == "enabled" {
			summary.PoliciesFound++
			if entry.RestrictedToTrustedLocations {
				summary.EnrollmentRestrictedToTrustedLocations = true
			}
		}
	}

	sort.Slice(summary.Policies, func(i, j int) bool {
		return summary.Policies[i].DisplayName < summary.Policies[j].DisplayName
	})

	return summary
}

// targetsMFARegistration returns true when the policy's
// conditions.applications.includeUserActions includes the MFA registration
// sentinel.
func targetsMFARegistration(p *types.ConditionalAccessPolicyDetail) bool {
	if p.Conditions == nil || p.Conditions.Applications == nil {
		return false
	}
	for _, action := range p.Conditions.Applications.IncludeUserActions {
		if action == mfaRegistrationUserAction {
			return true
		}
	}
	return false
}

// buildMFARegistrationEntry projects a CA policy into the summary entry
// shape, computing RestrictedToTrustedLocations from the policy's location
// condition + the trusted-by-ID lookup.
func buildMFARegistrationEntry(p *types.ConditionalAccessPolicyDetail, trustedByID map[string]bool) types.MFARegistrationPolicyEntry {
	entry := types.MFARegistrationPolicyEntry{
		ID:          p.ID,
		DisplayName: p.DisplayName,
		State:       p.State,
	}
	if p.Conditions != nil && p.Conditions.Applications != nil {
		entry.UserActions = p.Conditions.Applications.IncludeUserActions
	}
	if p.Conditions != nil && p.Conditions.Locations != nil {
		entry.IncludeLocations = p.Conditions.Locations.IncludeLocations
		entry.ExcludeLocations = p.Conditions.Locations.ExcludeLocations
	}
	if p.GrantControls != nil {
		entry.GrantControls = p.GrantControls.BuiltInControls
	}
	entry.RestrictedToTrustedLocations = isRestrictedToTrustedLocations(entry.IncludeLocations, trustedByID)
	return entry
}

// isRestrictedToTrustedLocations applies the spec'd rule:
//
//   - empty IncludeLocations → not restricted (no location condition at all)
//   - any "All" entry → not restricted (broad)
//   - every other entry is either "AllTrusted" or a GUID resolving to a
//     trusted named location → restricted
//
// A single non-trusted GUID poisons the set. An unknown GUID (location
// deleted but the policy still references it) is treated as non-trusted —
// conservative, matches the operator's expectation that the SaaS surface
// a finding when the policy has a broken reference.
func isRestrictedToTrustedLocations(includes []string, trustedByID map[string]bool) bool {
	if len(includes) == 0 {
		return false
	}
	for _, loc := range includes {
		switch loc {
		case caLocationAll:
			return false
		case caLocationAllTrusted:
			// trusted — continue
		default:
			if !trustedByID[loc] {
				return false
			}
		}
	}
	return true
}
