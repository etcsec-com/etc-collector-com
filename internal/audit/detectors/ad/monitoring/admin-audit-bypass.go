package monitoring

import (
	"context"
	"regexp"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// AdminAuditBypassDetector checks for admins that can bypass audit
type AdminAuditBypassDetector struct {
	audit.BaseDetector
}

// NewAdminAuditBypassDetector creates a new detector
func NewAdminAuditBypassDetector() *AdminAuditBypassDetector {
	return &AdminAuditBypassDetector{
		BaseDetector: audit.NewBaseDetector("ADMIN_AUDIT_BYPASS", audit.CategoryMonitoring),
	}
}

var protectedUsersPattern = regexp.MustCompile(`(?i)protected users`)

// Detect executes the detection
func (d *AdminAuditBypassDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// Find users with adminCount=1 who are enabled
	var adminUsers []types.User
	for _, user := range data.Users {
		if user.AdminCount && !user.Disabled {
			adminUsers = append(adminUsers, user)
		}
	}

	// Check for admins not in Protected Users group
	var adminsNotProtected []types.User
	for _, admin := range adminUsers {
		isInProtectedUsers := false
		for _, groupDN := range admin.MemberOf {
			if protectedUsersPattern.MatchString(groupDN) {
				isInProtectedUsers = true
				break
			}
		}
		if !isInProtectedUsers {
			adminsNotProtected = append(adminsNotProtected, admin)
		}
	}

	// Check for admins with old passwords (higher risk)
	sixMonthsAgo := data.Now.AddDate(0, -6, 0)
	var auditBypassRisk []types.User
	for _, admin := range adminsNotProtected {
		if admin.PasswordLastSet.IsZero() || admin.PasswordLastSet.Before(sixMonthsAgo) {
			auditBypassRisk = append(auditBypassRisk, admin)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "Administrators Can Bypass Audit",
		Description: "Privileged accounts not in Protected Users group with old passwords may bypass audit controls.",
		Count:       len(auditBypassRisk),
	}

	if len(auditBypassRisk) > 0 {
		if data.IncludeDetails {
			finding.AffectedEntities = helpers.ToAffectedUserEntities(auditBypassRisk)
		}
		finding.Details = map[string]interface{}{
			"totalAdmins":            len(adminUsers),
			"adminsNotProtected":     len(adminsNotProtected),
			"adminsWithOldPasswords": len(auditBypassRisk),
			"recommendation":         "Add admin accounts to Protected Users group and enforce regular password rotation.",
			"risks": []string{
				"Admins can clear security logs",
				"Compromised admin credentials may evade detection",
				"Audit policies may be disabled by compromised admin",
			},
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewAdminAuditBypassDetector())
}
