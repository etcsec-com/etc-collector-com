package gpo

import (
	"context"
	"fmt"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// OrphanedDetector checks for orphaned GPOs
type OrphanedDetector struct {
	audit.BaseDetector
}

// NewOrphanedDetector creates a new detector
func NewOrphanedDetector() *OrphanedDetector {
	return &OrphanedDetector{
		BaseDetector: audit.NewBaseDetector("GPO_ORPHANED", audit.CategoryGPO),
	}
}

// Detect executes the detection
func (d *OrphanedDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "Orphaned GPOs Detected",
		Description: "GPOs with mismatched AD objects and SYSVOL directories. Orphaned GPOs can cause processing errors and may indicate tampering.",
		Count:       0,
		Details: map[string]interface{}{
			"recommendation": "Compare AD GPOs with SYSVOL folders. Delete orphaned GPOs after verification.",
		},
	}

	// If SYSVOL scan data available, use it for accurate orphan detection
	if len(data.SYSVOLFindings) > 0 {
		var orphanDetails []string
		for _, sf := range data.SYSVOLFindings {
			if sf.Type == "orphaned_ldap" || sf.Type == "orphaned_sysvol" {
				name := sf.GPOName
				if name == "" {
					name = sf.GPOGUID
				}
				orphanDetails = append(orphanDetails, fmt.Sprintf("[%s] %s: %s", sf.Type, name, sf.Details))
			}
		}
		if len(orphanDetails) > 0 {
			finding.Count = len(orphanDetails)
			finding.Details["orphanedGPOs"] = orphanDetails
			return []types.Finding{finding}
		}
	}

	// Fallback: LDAP-only detection (GPOs missing SYSVOL path or name)
	var affected []types.GPO
	for _, gpo := range data.GPOs {
		hasSysvolPath := gpo.FilePath != ""
		hasName := gpo.DisplayName != "" || gpo.CN != ""
		if !hasSysvolPath || !hasName {
			affected = append(affected, gpo)
		}
	}

	finding.Count = len(affected)
	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedGPOEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewOrphanedDetector())
}
