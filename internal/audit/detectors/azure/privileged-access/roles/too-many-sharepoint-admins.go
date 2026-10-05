package roles

import (
	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// NewTooManySharePointAdminsDetector - >3 SharePoint Administrators
//
// Shares its implementation (thresholdRoleDetector) with the other
// too-many-*-admins detectors in this package; see too-many-privileged-roles.go.
func NewTooManySharePointAdminsDetector() *thresholdRoleDetector {
	return &thresholdRoleDetector{
		BaseDetector: audit.NewBaseDetector("PA_TOO_MANY_SHAREPOINT_ADMINS", audit.CategoryPrivilegedAccess),
		roleID:       types.AzureRoleSharePointAdmin,
		roleName:     "SharePoint Administrator",
		threshold:    3,
		recommended:  3,
		severity:     types.SeverityHigh,
		descFormat:   "More than %d users have SharePoint Administrator role (etc-collector default: ≤ %d; Microsoft's own cap is an aggregate <10 across all privileged roles).",
	}
}

func init() {
	audit.MustRegister(NewTooManySharePointAdminsDetector())
}
