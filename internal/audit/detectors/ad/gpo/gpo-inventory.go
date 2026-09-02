package gpo

// gpo-inventory.go emits one INFO_DOMAIN_GPO_INVENTORY finding per GPO, each
// carrying a fully-typed gpo AffectedEntity (asset-entities P2 §6, T_003).
//
// Severity is info — these findings exist to expose every GPO as a first-class
// asset to the SaaS /assets/gpos page, not to flag a vulnerability. Without
// them the page is empty on well-configured domains (GPOs with no finding are
// invisible), which is exactly the "good citizens are invisible" gap §6 fixes.
// GPOs referenced by other findings (WRITEDACL, etc.) keep emitting their own
// gpo entities with the same shape — no divergence.

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// GPOInventoryDetector emits the per-GPO inventory.
type GPOInventoryDetector struct {
	audit.BaseDetector
}

// NewGPOInventoryDetector creates the detector.
func NewGPOInventoryDetector() *GPOInventoryDetector {
	return &GPOInventoryDetector{
		BaseDetector: audit.NewBaseDetector("INFO_DOMAIN_GPO_INVENTORY", audit.CategoryGPO),
	}
}

// Detect builds one finding per GPO. Returns nil when no GPO was collected
// (audit ran against a tenant with permission issues or an empty domain).
func (d *GPOInventoryDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	if len(data.GPOs) == 0 {
		return nil
	}
	out := make([]types.Finding, 0, len(data.GPOs))
	for _, g := range data.GPOs {
		f := types.Finding{
			Type:        d.ID(),
			Severity:    types.SeverityInfo,
			Category:    string(d.Category()),
			Title:       "Group Policy Object",
			Description: "Inventory entry — exposes the GPO as a first-class asset to the SaaS (linked containers, permissions, WMI filter).",
			Count:       1,
		}
		if data.IncludeDetails {
			f.AffectedEntities = []types.AffectedEntity{audit.GPOEntity(g, data)}
		}
		out = append(out, f)
	}
	return out
}

func init() {
	audit.MustRegister(NewGPOInventoryDetector())
}
