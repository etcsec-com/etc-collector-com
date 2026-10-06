package pim

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// PIMNotEnabledDetector checks if PIM is configured for sensitive roles
type PIMNotEnabledDetector struct {
	audit.BaseDetector
}

// NewPIMNotEnabledDetector creates a new detector
func NewPIMNotEnabledDetector() *PIMNotEnabledDetector {
	return &PIMNotEnabledDetector{
		BaseDetector: audit.NewBaseDetector("PA_PIM_NOT_ENABLED", audit.CategoryPrivilegedAccess),
	}
}

// Detect executes the detection
func (d *PIMNotEnabledDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	sensitiveRoles := []string{
		"Global Administrator",
		"Privileged Role Administrator",
		"Security Administrator",
	}

	var directAssignments []types.RoleAssignment
	hasEligible := false

	for _, ra := range data.AzureRoleAssignments {
		// Check if sensitive role
		isSensitive := false
		for _, sensitive := range sensitiveRoles {
			if ra.RoleName == sensitive {
				isSensitive = true
				break
			}
		}

		if !isSensitive {
			continue
		}

		if ra.IsEligible {
			hasEligible = true
		} else if ra.AssignmentType == "direct" {
			directAssignments = append(directAssignments, ra)
		}
	}

	// If no eligible assignments for sensitive roles, PIM not configured
	if !hasEligible && len(directAssignments) > 0 {
		finding := types.Finding{
			Type:        d.ID(),
			Severity:    types.SeverityCritical,
			Category:    string(d.Category()),
			Title:       "PIM Not Configured for Privileged Roles",
			Description: "Privileged Identity Management (PIM) not enabled for sensitive admin roles. All assignments are permanent with standing privileges.",
			Count:       len(directAssignments),
			Details: map[string]interface{}{
				"recommendation": "Enable PIM for Global Administrator and other privileged roles",
				"benefit":        "Just-in-time access reduces standing privileges and attack surface",
			},
		}

		if data.IncludeDetails {
			finding.AffectedEntities = helpers.RoleAssignmentsToAffectedEntities(directAssignments)
		}

		return []types.Finding{finding}
	}

	return []types.Finding{}
}

func init() {
	audit.MustRegister(NewPIMNotEnabledDetector())
}
