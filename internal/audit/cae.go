// Package audit — Continuous Access Evaluation (CAE) summary builder
// (v3.1.39 §1).
//
// Pure post-collection aggregator. Walks data.AzureConditionalAccessPolicyDetails
// (already in memory from v3.1.38 §3) and produces audit.cae — the tenant-wide
// rollup the SaaS analyzer needs to render the CAE Coverage Card and emit
//   CAE_NOT_GLOBALLY_ENABLED
//   CAE_RESILIENCE_BYPASS_ALLOWED
//   CAE_CRITICAL_APPS_NOT_COVERED
//
// No additional Graph roundtrip — the upstream collector already pays for
// /identity/conditionalAccess/policies in v3.1.38 §3.

package audit

import (
	"math"

	"github.com/etcsec-com/etc-collector/pkg/types"
)

// Microsoft Graph application identifiers for the four critical Microsoft 365
// apps the SaaS analyzer treats as "must be covered by CAE". CA policies can
// target apps by:
//
//   - the literal "All" — covers every app
//   - the "Office365" group identifier — covers Exchange + SharePoint + Teams
//   - Office Online + adjacent apps
//   - a specific service principal GUID
//
// We treat an app as covered when at least one enabled CA policy with CAE in
// strictEnforcement mode includes it via any of those three mechanisms.
const (
	caeAppAll                = "All"
	caeAppOffice365Group     = "Office365"
	caeAppExchangeOnlineID   = "00000002-0000-0ff1-ce00-000000000000"
	caeAppSharePointOnlineID = "00000003-0000-0ff1-ce00-000000000000"
	caeAppTeamsID            = "cc15fd57-2c6c-4117-a88c-83b1d56b4bbe"
)

// BuildCAESummary derives the tenant-wide Continuous Access Evaluation rollup
// from the CA policies detail slice. Returns nil only if data is nil.
//
// version is stamped into the output so an audit JSON traces back to the
// exact helper logic that produced it.
func BuildCAESummary(data *DetectorData, version string) *types.CAESummary {
	if data == nil {
		return nil
	}

	summary := &types.CAESummary{
		CollectorVersion: version,
		ModesByPolicy:    map[string]string{},
	}

	if data.AzureConditionalAccessPolicyDetails == nil {
		// Slice nil = collection failed (Policy.Read.All scope likely
		// missing). The engine already emitted AZURE_CA_POLICIES_FAILED;
		// here we mark the summary unavailable and explain why.
		summary.Available = false
		summary.Reason = "Conditional Access policy detail not collected (Policy.Read.All scope likely missing)."
		return summary
	}

	summary.Available = true
	summary.PoliciesTotal = len(data.AzureConditionalAccessPolicyDetails)

	// Pass 1 — build modesByPolicy and counts.
	for i := range data.AzureConditionalAccessPolicyDetails {
		p := &data.AzureConditionalAccessPolicyDetails[i]
		mode := caeMode(p)
		// Map carries every policy ID, even when the control is absent
		// (empty string). The SaaS analyzer treats "" as "no CAE control
		// set on this policy".
		summary.ModesByPolicy[p.ID] = mode

		if !isPolicyEnabled(p) {
			continue
		}
		summary.PoliciesEnabledTotal++

		if mode == types.CAEModeStrictEnforcement {
			summary.PoliciesWithCAE++
		}
		if hasResilienceBypass(p) {
			summary.ResilienceDefaultsDisabledOnPolicies = append(
				summary.ResilienceDefaultsDisabledOnPolicies,
				types.CAEPolicyRef{ID: p.ID, DisplayName: p.DisplayName},
			)
		}
	}

	// Adoption % rounded to one decimal. Zero when the denominator is zero
	// (rather than NaN/Inf).
	if summary.PoliciesEnabledTotal > 0 {
		raw := float64(summary.PoliciesWithCAE) / float64(summary.PoliciesEnabledTotal) * 100.0
		summary.AdoptionPercent = math.Round(raw*10) / 10
	}

	// Pass 2 — critical apps coverage. Iterate over enabled+strictEnforcement
	// policies only; for each, check which critical apps it covers via "All",
	// "Office365" group, or specific GUID.
	for i := range data.AzureConditionalAccessPolicyDetails {
		p := &data.AzureConditionalAccessPolicyDetails[i]
		if !isPolicyEnabled(p) || caeMode(p) != types.CAEModeStrictEnforcement {
			continue
		}
		includes := includedApps(p)
		if includes == nil {
			continue
		}
		updateCriticalCoverage(&summary.CriticalAppsCoverage, includes)
	}

	// GloballyEnabled = at least one enabled+strict policy targets "All" or
	// "Office365" — heuristic for "the tenant has CAE on the broad surface".
	for i := range data.AzureConditionalAccessPolicyDetails {
		p := &data.AzureConditionalAccessPolicyDetails[i]
		if !isPolicyEnabled(p) || caeMode(p) != types.CAEModeStrictEnforcement {
			continue
		}
		for _, app := range includedApps(p) {
			if app == caeAppAll || app == caeAppOffice365Group {
				summary.GloballyEnabled = true
				break
			}
		}
		if summary.GloballyEnabled {
			break
		}
	}

	return summary
}

// caeMode reads sessionControls.continuousAccessEvaluation.mode for a policy.
// Returns "" when the control is absent.
func caeMode(p *types.ConditionalAccessPolicyDetail) string {
	if p.SessionControls == nil || p.SessionControls.ContinuousAccessEvaluation == nil {
		return ""
	}
	return p.SessionControls.ContinuousAccessEvaluation.Mode
}

// hasResilienceBypass reads sessionControls.disableResilienceDefaults.
// Returns true when the bool is explicitly true (nil or false → false).
func hasResilienceBypass(p *types.ConditionalAccessPolicyDetail) bool {
	if p.SessionControls == nil || p.SessionControls.DisableResilienceDefaults == nil {
		return false
	}
	return *p.SessionControls.DisableResilienceDefaults
}

// isPolicyEnabled returns true for state == "enabled" (case-sensitive,
// matching Graph). reportOnly and disabled don't count.
func isPolicyEnabled(p *types.ConditionalAccessPolicyDetail) bool {
	return p.State == "enabled"
}

// includedApps returns the conditions.applications.includeApplications slice,
// or nil if absent.
func includedApps(p *types.ConditionalAccessPolicyDetail) []string {
	if p.Conditions == nil || p.Conditions.Applications == nil {
		return nil
	}
	return p.Conditions.Applications.IncludeApplications
}

// updateCriticalCoverage flips the four coverage flags based on what a single
// policy's includeApplications targets. Idempotent — once a flag is true it
// stays true across calls.
func updateCriticalCoverage(cov *types.CAECriticalAppsCoverage, includes []string) {
	for _, app := range includes {
		switch app {
		case caeAppAll:
			cov.Office365 = true
			cov.ExchangeOnline = true
			cov.SharePointOnline = true
			cov.Teams = true
			return
		case caeAppOffice365Group:
			cov.Office365 = true
			cov.ExchangeOnline = true
			cov.SharePointOnline = true
			cov.Teams = true
		case caeAppExchangeOnlineID:
			cov.ExchangeOnline = true
		case caeAppSharePointOnlineID:
			cov.SharePointOnline = true
		case caeAppTeamsID:
			cov.Teams = true
		}
	}
}
