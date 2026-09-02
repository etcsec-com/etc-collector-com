package other

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// DisplaySpecifiersChangesDetector detects recent modifications to Display Specifier objects
type DisplaySpecifiersChangesDetector struct {
	audit.BaseDetector
}

// NewDisplaySpecifiersChangesDetector creates a new detector
func NewDisplaySpecifiersChangesDetector() *DisplaySpecifiersChangesDetector {
	return &DisplaySpecifiersChangesDetector{
		BaseDetector: audit.NewBaseDetector("DISPLAY_SPECIFIER_CHANGES", audit.CategoryAdvanced),
	}
}

// Detect executes the detection
func (d *DisplaySpecifiersChangesDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	count := len(data.DisplaySpecifierChanges)

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityInfo,
		Category:    string(d.Category()),
		Title:       "Display Specifier Objects Recently Modified",
		Description: "Display Specifier objects under CN=DisplaySpecifiers,CN=Configuration have been modified within the last 90 days. These objects control UI behavior in AD management tools and could be weaponized for code execution when admins open AD tools.",
		Count:       count,
	}

	if data.IncludeDetails && len(data.DisplaySpecifierChanges) > 0 {
		entities := make([]types.AffectedEntity, 0, len(data.DisplaySpecifierChanges))
		for _, dn := range data.DisplaySpecifierChanges {
			entities = append(entities, types.AffectedEntity{
				Type: "displaySpecifier",
				Name: dn,
			})
		}
		finding.AffectedEntities = entities
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewDisplaySpecifiersChangesDetector())
}
