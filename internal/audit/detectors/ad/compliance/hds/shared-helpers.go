package hds

import (
	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// wrap is shared by every detector in this package.
func wrap(d audit.Detector, title, description string, sev types.Severity, count int) []types.Finding {
	return []types.Finding{{
		Type:        d.ID(),
		Severity:    sev,
		Category:    string(d.Category()),
		Title:       title,
		Description: description,
		Count:       count,
	}}
}
