package roles

import (
	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// NewTooManyAppAdminsDetector - >5 Application Administrators
//
// Shares its implementation (thresholdRoleDetector) with the other
// too-many-*-admins detectors in this package; see too-many-privileged-roles.go.
func NewTooManyAppAdminsDetector() *thresholdRoleDetector {
	return &thresholdRoleDetector{
		BaseDetector: audit.NewBaseDetector("PA_TOO_MANY_APP_ADMINS", audit.CategoryPrivilegedAccess),
		roleID:       types.AzureRoleAppAdmin,
		roleName:     "Application Administrator",
		threshold:    5,
		recommended:  5,
		severity:     types.SeverityHigh,
		descFormat:   "More than %d users have Application Administrator role (etc-collector default: ≤ %d; Microsoft's own cap is an aggregate <10 across all privileged roles). This role can manage app secrets and consent.",
	}
}

func init() {
	audit.MustRegister(NewTooManyAppAdminsDetector())
}
