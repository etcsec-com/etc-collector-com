package pim

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// PIMNoApprovalRequiredDetector detects PIM-eligible roles without approval requirement.
//
// ra.RequiresApproval is real per-role PIM policy data (the role management
// policy's IsApprovalRequired rule, collected per assignment), not a guess -
// see internal/providers/azure/client.go's role-assignment enrichment.
// Microsoft documents the approval workflow itself (Microsoft Learn, "Approve
// or deny requests for Microsoft Entra roles in Privileged Identity
// Management", learn.microsoft.com/en-us/entra/id-governance/
// privileged-identity-management/pim-approval-workflow) but does not mandate
// approval for any specific fixed set of roles - that choice is left to each
// organization. The five roles below are an etc-collector product shortlist
// of commonly high-impact roles, not a Microsoft-documented requirement.
type PIMNoApprovalRequiredDetector struct {
	audit.BaseDetector
}

// NewPIMNoApprovalRequiredDetector creates a new detector
func NewPIMNoApprovalRequiredDetector() *PIMNoApprovalRequiredDetector {
	return &PIMNoApprovalRequiredDetector{
		BaseDetector: audit.NewBaseDetector("PA_PIM_NO_APPROVAL_REQUIRED", audit.CategoryPrivilegedAccess),
	}
}

// Detect executes the detection
func (d *PIMNoApprovalRequiredDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.RoleAssignment

	sensitiveRoles := []string{
		"Global Administrator",
		"Privileged Role Administrator",
		"Security Administrator",
		"Exchange Administrator",
		"SharePoint Administrator",
	}

	for _, ra := range data.AzureRoleAssignments {
		if !ra.IsEligible {
			continue
		}

		// Check if sensitive role
		isSensitive := false
		for _, sensitive := range sensitiveRoles {
			if ra.RoleName == sensitive {
				isSensitive = true
				break
			}
		}

		if isSensitive && !ra.RequiresApproval {
			affected = append(affected, ra)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "PIM Activation Without Approval",
		Description: "PIM-eligible privileged roles can be activated without approval. Approval provides an additional security checkpoint for sensitive role activations.",
		Count:       len(affected),
		Details: map[string]interface{}{
			"recommendation": "Require approval for Global Administrator and other highly privileged role activations",
		},
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.RoleAssignmentsToAffectedEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewPIMNoApprovalRequiredDetector())
}
