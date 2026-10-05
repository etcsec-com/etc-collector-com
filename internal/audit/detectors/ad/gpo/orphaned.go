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

// Detect executes the detection.
//
// Two different checks share this ID depending on what was collected:
//   - With SYSVOL access (data.SYSVOLFindings populated), this is a real
//     orphan check: AD GPO objects are compared against actual SYSVOL
//     directories.
//   - Without SYSVOL access, the fallback below is a narrower proxy - it
//     only catches a GPO whose LDAP attributes (gPCFileSysPath/displayName)
//     are themselves missing or empty. That is a real, verified signal
//     (plant/revert-confirmed: deleting gPCFileSysPath flips this from 0 to
//     1 - see docs/security-validation/results/t163-manual/VERDICT-T163.md),
//     but it is not equivalent to comparing against SYSVOL: a GPO whose
//     LDAP object is intact but whose SYSVOL folder is missing (or vice
//     versa) is invisible to this fallback. No official source defines this
//     fallback as an orphan check; the Description is worded to match what
//     each path actually measures instead of promising SYSVOL-grade
//     detection in both cases.
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

	// Fallback: LDAP-only detection (GPOs missing SYSVOL path or name). This
	// is a narrower proxy than the SYSVOLFindings path above - see the
	// Detect doc comment.
	finding.Description = "GPO AD objects with a missing gPCFileSysPath or display name/CN attribute. SYSVOL was not scanned for this audit, so this is a narrower proxy for orphaned GPOs - it cannot detect a SYSVOL folder missing its AD object, or vice versa, only an incomplete AD-side GPO object."
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
