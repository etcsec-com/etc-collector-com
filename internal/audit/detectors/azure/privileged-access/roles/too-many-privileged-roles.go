package roles

import (
	"context"
	"fmt"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// This file used to hold five "too many admins" detectors (Privileged Role
// Admin, Security Admin, Exchange Admin, SharePoint Admin, Application
// Admin); each now lives in its own file (too-many-privileged-role-admins.go,
// too-many-security-admins.go, too-many-exchange-admins.go, too-many-
// sharepoint-admins.go, too-many-app-admins.go). What remains here is the
// shared implementation those five factory functions all construct.

// thresholdRoleDetector is the shared implementation behind the per-role
// "too many admins" detectors (Privileged Role Admin, Security Admin, Exchange
// Admin, SharePoint Admin, Application Admin). Follows the same pattern as
// TooManyGlobalAdminsDetector but with role-specific thresholds.
//
// The only Microsoft-documented numeric threshold for privileged role counts
// is an aggregate one: "Limit the number of privileged role assignments to
// less than 10" across ALL privileged roles combined (Microsoft Learn, "Best
// practices for Microsoft Entra roles", learn.microsoft.com/en-us/entra/
// identity/role-based-access-control/best-practices, best practice #6).
// Microsoft does not publish a separate numeric cap per individual role, so
// the per-role thresholds below (3 for Privileged Role/Security/Exchange/
// SharePoint Administrator, 5 for Application Administrator) are
// etc-collector product defaults, not Microsoft-mandated per-role limits.
type thresholdRoleDetector struct {
	audit.BaseDetector
	roleID      string
	roleName    string
	threshold   int
	severity    types.Severity
	descFormat  string
	recommended int
}

func (d *thresholdRoleDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var matches []types.RoleAssignment
	for _, ra := range data.AzureRoleAssignments {
		if ra.RoleID == d.roleID {
			matches = append(matches, ra)
		}
	}

	count := 0
	if len(matches) > d.threshold {
		count = len(matches)
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    d.severity,
		Category:    string(d.Category()),
		Title:       fmt.Sprintf("Too Many %ss", d.roleName),
		Description: fmt.Sprintf(d.descFormat, len(matches), d.recommended),
		Count:       count,
	}
	if count > 0 {
		finding.AffectedEntities = helpers.ToAffectedRoleAssignmentEntities(matches)
	}
	return []types.Finding{finding}
}
