package compliance

import (
	"sort"

	"github.com/etcsec-com/etc-collector/internal/audit/compliance/catalogs"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// CalculatePerFramework derives a score and a complete checklist for every
// framework declared in AllFrameworks.
//
// The catalog (one per framework, see internal/audit/compliance/catalogs/)
// is the source of truth: it lists every official control the framework
// publishes. For each official control the function emits one
// EvaluatedControl with one of these statuses:
//
//   - "manual"          — the control is organisational, contractual or
//     physical; not auditable from LDAP/SYSVOL/registry.
//     (catalog Automatable=false)
//   - "failed"          — at least one finding triggered for this control.
//   - "passed"          — at least one detector covers this control AND no
//     triggered finding for it.
//   - "not_applicable"  — the control is automatable but no detector in the
//     current build covers it (e.g. Pro detector missing
//     from Community build, or Cloud-only control).
//
// Score formula : passed / (total - manual - notApplicable) * 100, rounded
// to one decimal. Manual and not_applicable controls are excluded from the
// denominator so dashboards show a meaningful score.
//
// Returns the canonical types.FrameworkScore (defined in pkg/types so the
// JSON shape is shared across packages).
func CalculatePerFramework(findings []types.Finding) []types.FrameworkScore {
	// Build the set of controls that have a triggered finding. Per framework,
	// per control, we keep the list of detector IDs and the worst severity.
	type triggeredControl struct {
		findingTypes map[string]struct{}
		severity     string // worst severity seen
	}
	triggered := map[string]map[string]*triggeredControl{}
	for _, f := range findings {
		if f.Count == 0 {
			continue
		}
		for _, m := range f.Compliance {
			if triggered[m.Framework] == nil {
				triggered[m.Framework] = map[string]*triggeredControl{}
			}
			tc := triggered[m.Framework][m.Control]
			if tc == nil {
				tc = &triggeredControl{findingTypes: map[string]struct{}{}}
				triggered[m.Framework][m.Control] = tc
			}
			tc.findingTypes[f.Type] = struct{}{}
			fSev := string(f.Severity)
			if severityRank(fSev) > severityRank(tc.severity) {
				tc.severity = fSev
			}
		}
	}

	// Build the set of controls that ETC has at least one detector mapped to.
	// A control with a detector but no triggered finding is "passed".
	// A control without any detector is "not_applicable" (no automation in
	// this build).
	covered := map[string]map[string]struct{}{}
	for _, ms := range mappings {
		for _, m := range ms {
			if covered[m.Framework] == nil {
				covered[m.Framework] = map[string]struct{}{}
			}
			covered[m.Framework][m.Control] = struct{}{}
		}
	}

	out := make([]types.FrameworkScore, 0, len(AllFrameworks))
	for _, fw := range AllFrameworks {
		cat := catalogs.Get(fw)
		if cat == nil {
			// Framework declared but no catalog yet — skip rather than emit
			// an empty score that would mislead consumers.
			continue
		}

		evaluated := make([]types.EvaluatedControl, 0, len(cat.Controls))
		var passed, failed, manual, notApplicable int
		failedCodes := []string{}
		for _, ctrl := range cat.Controls {
			ec := types.EvaluatedControl{
				Code:       ctrl.Code,
				Title:      ctrl.Title,
				OfficialFR: ctrl.OfficialFR, // v3.1.20 — propagate FR title to JSON
				Section:    ctrl.Section,
			}
			switch {
			case !ctrl.Automatable:
				ec.Status = "manual"
				ec.ManualOnly = true
				ec.Rationale = ctrl.Rationale
				manual++
			default:
				if tc, hit := triggered[fw][ctrl.Code]; hit {
					ec.Status = "failed"
					ec.Severity = tc.severity
					ec.FindingTypes = sortedKeys(tc.findingTypes)
					failed++
					failedCodes = append(failedCodes, ctrl.Code)
				} else if _, hasDetector := covered[fw][ctrl.Code]; hasDetector {
					ec.Status = "passed"
					passed++
				} else {
					// Automatable per catalog, but no detector in this build
					// touches the control.
					ec.Status = "not_applicable"
					ec.Rationale = "No detector in the current build covers this control"
					notApplicable++
				}
			}
			evaluated = append(evaluated, ec)
		}

		denom := passed + failed
		var score float64
		if denom > 0 {
			score = float64(passed) / float64(denom) * 100
		}

		fs := types.FrameworkScore{
			Framework:             fw,
			Score:                 round1(score),
			Rating:                ratingFromScore(score),
			ControlsTotal:         len(cat.Controls),
			ControlsPassed:        passed,
			ControlsFailed:        failed,
			ControlsManual:        manual,
			ControlsNotApplicable: notApplicable,
			EvaluatedControls:     evaluated,
		}
		if len(failedCodes) > 0 {
			sort.Strings(failedCodes)
			fs.FailedControls = failedCodes
		}
		// Maturity axes — only ANSSI_PA099 today.
		fs.MaturityAxes = computeMaturityAxes(fw, evaluated)
		out = append(out, fs)
	}
	return out
}

// severityRank ranks severity strings so we can keep "worst" per control.
func severityRank(s string) int {
	switch s {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	case "info":
		return 1
	}
	return 0
}

// sortedKeys returns the keys of m, sorted alphabetically.
func sortedKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func ratingFromScore(s float64) string {
	switch {
	case s >= 95:
		return "excellent"
	case s >= 80:
		return "low"
	case s >= 60:
		return "medium"
	case s >= 40:
		return "high"
	default:
		return "critical"
	}
}

func round1(v float64) float64 {
	return float64(int(v*10+0.5)) / 10
}
