package exclusions

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// UserExclusionsStaleDetector checks for CA policies with user-level exclusions
type UserExclusionsStaleDetector struct {
	audit.BaseDetector
}

// NewUserExclusionsStaleDetector creates a new detector
func NewUserExclusionsStaleDetector() *UserExclusionsStaleDetector {
	return &UserExclusionsStaleDetector{
		BaseDetector: audit.NewBaseDetector("CA_USER_EXCLUSIONS_STALE", audit.CategoryConditionalAccess),
	}
}

// containsStr checks if a slice contains a string
func containsStr(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}

// hasOnlyGuestsOrExternal checks if the exclusions only contain GuestsOrExternalUsers
func hasOnlyGuestsOrExternal(excludeUsers []string) bool {
	if len(excludeUsers) == 0 {
		return false
	}
	for _, u := range excludeUsers {
		if u != "GuestsOrExternalUsers" {
			return false
		}
	}
	return true
}

// Detect executes the detection
//
// The ID and struct name say "Stale" (implying a time-based, e.g.
// last-reviewed-date check), but no such check is implemented or possible
// from currently-collected data (no exclusion-added timestamp is captured).
// What's actually measured is a different, real signal: exclusion by named
// user instead of by group, a maintainability/auditability concern (per
// Microsoft's own Conditional Access exclusion guidance - see
// ca-excessive-exclusions.go / ca-group-exclusion-large.go for the citation)
// distinct from "this exclusion has gone unreviewed for a long time". Title
// and description now describe that, not staleness. The detector ID
// (CA_USER_EXCLUSIONS_STALE) is left unchanged - renaming it would break
// existing report/API consumers keyed on it.
func (d *UserExclusionsStaleDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.ConditionalAccessPolicy

	for _, p := range data.AzureConditionalAccessPolicies {
		if p.State != "enabled" {
			continue
		}

		if len(p.ExcludeUsers) > 0 && !hasOnlyGuestsOrExternal(p.ExcludeUsers) {
			affected = append(affected, p)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "CA Policies Excluding Named Users Instead of Groups",
		Description: "CA policies exclude individually-named users rather than a group. Named-user exclusions are harder to manage and audit over time than a reviewable group membership (this check does not measure how long an exclusion has existed).",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = make([]types.AffectedEntity, len(affected))
		for i, p := range affected {
			finding.AffectedEntities[i] = types.AffectedEntity{
				Type: "conditionalAccessPolicy",
				DN:   p.ID,
				Name: p.DisplayName,
			}
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewUserExclusionsStaleDetector())
}
