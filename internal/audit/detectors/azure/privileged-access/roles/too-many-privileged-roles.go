package roles

import (
	"context"
	"fmt"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// thresholdRoleDetector is the shared implementation behind the per-role
// "too many admins" detectors (Privileged Role Admin, Security Admin, Exchange
// Admin, SharePoint Admin, Application Admin). Follows the same pattern as
// TooManyGlobalAdminsDetector but with role-specific thresholds.
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

// NewTooManyPrivilegedRoleAdminsDetector — >3 Privileged Role Administrators
func NewTooManyPrivilegedRoleAdminsDetector() *thresholdRoleDetector {
	return &thresholdRoleDetector{
		BaseDetector: audit.NewBaseDetector("PA_TOO_MANY_PRIVILEGED_ROLE_ADMINS", audit.CategoryPrivilegedAccess),
		roleID:       types.AzureRolePrivilegedRoleAdmin,
		roleName:     "Privileged Role Administrator",
		threshold:    3,
		recommended:  3,
		severity:     types.SeverityCritical,
		descFormat:   "More than %d users have Privileged Role Administrator role (recommended: ≤ %d). This role can grant any other role.",
	}
}

// NewTooManySecurityAdminsDetector — >3 Security Administrators
func NewTooManySecurityAdminsDetector() *thresholdRoleDetector {
	return &thresholdRoleDetector{
		BaseDetector: audit.NewBaseDetector("PA_TOO_MANY_SECURITY_ADMINS", audit.CategoryPrivilegedAccess),
		roleID:       types.AzureRoleSecurityAdmin,
		roleName:     "Security Administrator",
		threshold:    3,
		recommended:  3,
		severity:     types.SeverityHigh,
		descFormat:   "More than %d users have Security Administrator role (recommended: ≤ %d).",
	}
}

// NewTooManyExchangeAdminsDetector — >3 Exchange Administrators
func NewTooManyExchangeAdminsDetector() *thresholdRoleDetector {
	return &thresholdRoleDetector{
		BaseDetector: audit.NewBaseDetector("PA_TOO_MANY_EXCHANGE_ADMINS", audit.CategoryPrivilegedAccess),
		roleID:       types.AzureRoleExchangeAdmin,
		roleName:     "Exchange Administrator",
		threshold:    3,
		recommended:  3,
		severity:     types.SeverityHigh,
		descFormat:   "More than %d users have Exchange Administrator role (recommended: ≤ %d).",
	}
}

// NewTooManySharePointAdminsDetector — >3 SharePoint Administrators
func NewTooManySharePointAdminsDetector() *thresholdRoleDetector {
	return &thresholdRoleDetector{
		BaseDetector: audit.NewBaseDetector("PA_TOO_MANY_SHAREPOINT_ADMINS", audit.CategoryPrivilegedAccess),
		roleID:       types.AzureRoleSharePointAdmin,
		roleName:     "SharePoint Administrator",
		threshold:    3,
		recommended:  3,
		severity:     types.SeverityHigh,
		descFormat:   "More than %d users have SharePoint Administrator role (recommended: ≤ %d).",
	}
}

// NewTooManyAppAdminsDetector — >5 Application Administrators
func NewTooManyAppAdminsDetector() *thresholdRoleDetector {
	return &thresholdRoleDetector{
		BaseDetector: audit.NewBaseDetector("PA_TOO_MANY_APP_ADMINS", audit.CategoryPrivilegedAccess),
		roleID:       types.AzureRoleAppAdmin,
		roleName:     "Application Administrator",
		threshold:    5,
		recommended:  5,
		severity:     types.SeverityHigh,
		descFormat:   "More than %d users have Application Administrator role (recommended: ≤ %d). This role can manage app secrets and consent.",
	}
}

func init() {
	audit.MustRegister(NewTooManyPrivilegedRoleAdminsDetector())
	audit.MustRegister(NewTooManySecurityAdminsDetector())
	audit.MustRegister(NewTooManyExchangeAdminsDetector())
	audit.MustRegister(NewTooManySharePointAdminsDetector())
	audit.MustRegister(NewTooManyAppAdminsDetector())
}
