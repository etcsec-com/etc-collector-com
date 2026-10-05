package roles

import (
	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// NewTooManySecurityAdminsDetector - >3 Security Administrators
//
// Shares its implementation (thresholdRoleDetector) with the other
// too-many-*-admins detectors in this package; see too-many-privileged-roles.go.
func NewTooManySecurityAdminsDetector() *thresholdRoleDetector {
	return &thresholdRoleDetector{
		BaseDetector: audit.NewBaseDetector("PA_TOO_MANY_SECURITY_ADMINS", audit.CategoryPrivilegedAccess),
		roleID:       types.AzureRoleSecurityAdmin,
		roleName:     "Security Administrator",
		threshold:    3,
		recommended:  3,
		severity:     types.SeverityHigh,
		descFormat:   "More than %d users have Security Administrator role (etc-collector default: ≤ %d; Microsoft's own cap is an aggregate <10 across all privileged roles).",
	}
}

func init() {
	audit.MustRegister(NewTooManySecurityAdminsDetector())
}
