package organization

// ou-inventory.go emits one INFO_DOMAIN_OU_INVENTORY finding per OU, each
// carrying a fully-typed ou AffectedEntity (asset-entities P2 §6, T_003).
//
// Severity is info — these findings exist to expose every OU as a first-class
// asset to the SaaS /assets/ous page, not to flag a vulnerability. Without them
// the page is empty on well-configured domains (OUs with no finding are
// invisible). Mirrors the DC/GPO eager-inventory pattern.

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// OUInventoryDetector emits the per-OU inventory.
type OUInventoryDetector struct {
	audit.BaseDetector
}

// NewOUInventoryDetector creates the detector.
func NewOUInventoryDetector() *OUInventoryDetector {
	return &OUInventoryDetector{
		BaseDetector: audit.NewBaseDetector("INFO_DOMAIN_OU_INVENTORY", audit.CategoryPermissions),
	}
}

// Detect builds one finding per OU. Returns nil when no OU was collected.
func (d *OUInventoryDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	if len(data.OUs) == 0 {
		return nil
	}
	out := make([]types.Finding, 0, len(data.OUs))
	for _, ou := range data.OUs {
		f := types.Finding{
			Type:        d.ID(),
			Severity:    types.SeverityInfo,
			Category:    string(d.Category()),
			Title:       "Organizational Unit",
			Description: "Inventory entry — exposes the OU as a first-class asset to the SaaS (linked GPOs, direct-child census, delegations).",
			Count:       1,
		}
		if data.IncludeDetails {
			f.AffectedEntities = []types.AffectedEntity{audit.OUEntity(ou, data)}
		}
		out = append(out, f)
	}
	return out
}

func init() {
	audit.MustRegister(NewOUInventoryDetector())
}
