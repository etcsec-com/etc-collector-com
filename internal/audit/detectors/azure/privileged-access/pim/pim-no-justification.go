package pim

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// PIMNoJustificationDetector detects PIM-eligible roles without justification requirement
type PIMNoJustificationDetector struct {
	audit.BaseDetector
}

// NewPIMNoJustificationDetector creates a new detector
func NewPIMNoJustificationDetector() *PIMNoJustificationDetector {
	return &PIMNoJustificationDetector{
		BaseDetector: audit.NewBaseDetector("PA_PIM_NO_JUSTIFICATION", audit.CategoryPrivilegedAccess),
	}
}

// Detect executes the detection
func (d *PIMNoJustificationDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.RoleAssignment

	for _, ra := range data.AzureRoleAssignments {
		if !ra.IsEligible {
			continue
		}

		if !ra.RequiresJustification {
			affected = append(affected, ra)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "PIM Activation Without Justification",
		Description: "PIM role activations don't require justification. Justification provides audit trail and accountability for privilege use.",
		Count:       len(affected),
		Details: map[string]interface{}{
			"recommendation": "Enable justification requirement for all PIM role activations",
		},
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.RoleAssignmentsToAffectedEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewPIMNoJustificationDetector())
}
