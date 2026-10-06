package roles

import (
	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// NewTooManyPrivilegedRoleAdminsDetector - >3 Privileged Role Administrators
//
// Shares its implementation (thresholdRoleDetector) with the other
// too-many-*-admins detectors in this package; see too-many-privileged-roles.go.
func NewTooManyPrivilegedRoleAdminsDetector() *thresholdRoleDetector {
	return &thresholdRoleDetector{
		BaseDetector: audit.NewBaseDetector("PA_TOO_MANY_PRIVILEGED_ROLE_ADMINS", audit.CategoryPrivilegedAccess),
		roleID:       types.AzureRolePrivilegedRoleAdmin,
		roleName:     "Privileged Role Administrator",
		threshold:    3,
		recommended:  3,
		severity:     types.SeverityCritical,
		descFormat:   "More than %d users have Privileged Role Administrator role (etc-collector default: ≤ %d; Microsoft's own cap is an aggregate <10 across all privileged roles). This role can grant any other role.",
	}
}

func init() {
	audit.MustRegister(NewTooManyPrivilegedRoleAdminsDetector())
}
