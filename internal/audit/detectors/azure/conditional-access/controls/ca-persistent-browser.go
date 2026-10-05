package controls

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// PersistentBrowserEnabledDetector checks for CA policies allowing persistent browser sessions
type PersistentBrowserEnabledDetector struct {
	audit.BaseDetector
}

// NewPersistentBrowserEnabledDetector creates a new detector
func NewPersistentBrowserEnabledDetector() *PersistentBrowserEnabledDetector {
	return &PersistentBrowserEnabledDetector{
		BaseDetector: audit.NewBaseDetector("CA_PERSISTENT_BROWSER_ENABLED", audit.CategoryConditionalAccess),
	}
}

// Detect executes the detection
//
// Source: Microsoft Learn, "persistentBrowserSessionControl resource type"
// / "Require reauthentication with Conditional Access"
// (learn.microsoft.com/en-us/entra/identity/conditional-access/
// policy-all-users-persistent-browser) - sessionControls.persistentBrowser.
// mode is "always" or "never"; "always" is exactly "users stay signed in
// after closing and reopening their browser", matching this check and its
// description. Confirmed correct as implemented; not empirically observed
// against a live tenant yet (no policy in the lab sets PersistentBrowserMode
// == "always" - status "never_observed", not "verified"), so this remains
// "non vu" in practice, not a code defect.
func (d *PersistentBrowserEnabledDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.ConditionalAccessPolicy

	for _, p := range data.AzureConditionalAccessPolicies {
		if p.State == "enabled" && p.PersistentBrowserMode == "always" {
			affected = append(affected, p)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "Persistent Browser Session Allowed",
		Description: "CA policies allow persistent browser sessions. Users remain signed in indefinitely on shared devices.",
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
	audit.MustRegister(NewPersistentBrowserEnabledDetector())
}
