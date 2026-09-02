package trusts

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// ForestTransitiveDetector detects transitive forest trusts
type ForestTransitiveDetector struct {
	audit.BaseDetector
}

// NewForestTransitiveDetector creates a new detector
func NewForestTransitiveDetector() *ForestTransitiveDetector {
	return &ForestTransitiveDetector{
		BaseDetector: audit.NewBaseDetector("TRUST_FOREST_TRANSITIVE", audit.CategoryTrusts),
	}
}

// Detect executes the detection
func (d *ForestTransitiveDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affectedNames []string

	for _, t := range data.Trusts {
		// Check for forest trusts (which are transitive by nature)
		if t.TrustType == "Forest" {
			affectedNames = append(affectedNames, t.TargetDomain)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "Transitive Forest Trust",
		Description: "Forest trust is transitive, meaning all domains in the trusted forest can access this domain. This significantly increases the trust boundary.",
		Count:       len(affectedNames),
	}

	if len(affectedNames) > 0 {
		finding.Details = map[string]interface{}{
			"recommendation": "Review necessity of forest trust. Consider selective authentication and SID filtering.",
		}
	}

	if data.IncludeDetails && len(affectedNames) > 0 {
		entities := make([]types.AffectedEntity, len(affectedNames))
		for i, name := range affectedNames {
			entities[i] = types.AffectedEntity{
				Type:        "trust",
				DisplayName: name,
			}
		}
		finding.AffectedEntities = entities
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewForestTransitiveDetector())
}
