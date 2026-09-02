package trusts

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// InactiveDetector detects inactive trust relationships
type InactiveDetector struct {
	audit.BaseDetector
}

// NewInactiveDetector creates a new detector
func NewInactiveDetector() *InactiveDetector {
	return &InactiveDetector{
		BaseDetector: audit.NewBaseDetector("TRUST_INACTIVE", audit.CategoryTrusts),
	}
}

// Detect executes the detection
func (d *InactiveDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// Note: The current Trust type doesn't have a whenChanged field
	// This detector would need an extended Trust type to properly detect inactive trusts
	// For now, we'll return an empty finding as the data model doesn't support this check
	var affectedNames []string

	// If we had access to whenChanged, we would do:
	// now := time.Now()
	// sixMonthsAgo := now.AddDate(0, -6, 0)
	// for _, t := range data.Trusts {
	//     if t.WhenChanged.Before(sixMonthsAgo) {
	//         affectedNames = append(affectedNames, t.TargetDomain)
	//     }
	// }

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "Inactive Trust Relationship",
		Description: "Trust relationship has not been modified in over 180 days. May indicate an abandoned or forgotten trust that should be reviewed for necessity.",
		Count:       len(affectedNames),
	}

	if len(affectedNames) > 0 {
		finding.Details = map[string]interface{}{
			"recommendation": "Review necessity of inactive trusts. Remove trusts that are no longer needed to reduce attack surface.",
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
	audit.MustRegister(NewInactiveDetector())
}
