package pr001

import (
	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// wrapFinding is shared by both detectors in this package.
func wrapFinding(d audit.Detector, title, description string, sev types.Severity, count int, entities []types.AffectedEntity) []types.Finding {
	f := types.Finding{
		Type:        d.ID(),
		Severity:    sev,
		Category:    string(d.Category()),
		Title:       title,
		Description: description,
		Count:       count,
	}
	if count > 0 && len(entities) > 0 {
		f.AffectedEntities = entities
	}
	return []types.Finding{f}
}
