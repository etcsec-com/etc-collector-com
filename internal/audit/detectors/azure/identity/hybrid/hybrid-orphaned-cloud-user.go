package hybrid

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// HybridOrphanedCloudUserDetector flags cloud user objects whose
// AzureOnPremisesSyncEnabled is true but who no longer appear resolvable
// against any on-premises principal. In practice this means their
// AzureOnPremisesSyncEnabled flag is set but the collector has no matching
// on-prem sync state.
//
// Partially matches the intent behind Purple Knight's hybrid category.
type HybridOrphanedCloudUserDetector struct {
	audit.BaseDetector
}

func NewHybridOrphanedCloudUserDetector() *HybridOrphanedCloudUserDetector {
	return &HybridOrphanedCloudUserDetector{
		BaseDetector: audit.NewBaseDetector("HYBRID_ORPHANED_CLOUD_USER", audit.CategoryIdentity),
	}
}

func (d *HybridOrphanedCloudUserDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.User
	for i := range data.Users {
		u := &data.Users[i]
		// Only consider Azure-origin users (they have one of the Azure fields populated).
		if u.AzureOnPremisesSyncEnabled == nil || !*u.AzureOnPremisesSyncEnabled {
			continue
		}
		// Disabled + synced is a plain state observation, not a diagnosis. A
		// disabled synced account is the NORMAL, expected outcome of routine
		// on-prem offboarding (disable before delete is standard practice)
		// and is not, by itself, evidence of a failed sync or an orphaned
		// object - no Microsoft source documents "disabled + synced" as a
		// sync-failure signature.
		if u.AzureAccountEnabled != nil && !*u.AzureAccountEnabled {
			affected = append(affected, *u)
		}
	}

	finding := types.Finding{
		Type:     d.ID(),
		Severity: types.SeverityMedium,
		Category: string(d.Category()),
		Title:    "Disabled Hybrid-Synced User Account",
		Description: "Cloud user accounts flagged as on-prem synced are in a disabled state in " +
			"Entra ID. This is a routine hygiene signal, not a proven sync failure: a disabled " +
			"synced account is the normal, expected state right after on-prem offboarding. " +
			"Review the list to confirm each disablement was intentional and, where it wasn't, " +
			"investigate the on-prem sync.",
		Count: len(affected),
		Details: map[string]interface{}{
			"recommendation": "Confirm each listed account's on-prem disablement was intentional; investigate Azure AD Connect only for accounts where it was not.",
		},
	}
	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
	}
	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewHybridOrphanedCloudUserDetector())
}
