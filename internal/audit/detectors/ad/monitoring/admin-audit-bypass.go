package monitoring

import (
	"context"
	"regexp"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// AdminAuditBypassDetector checks for privileged accounts left outside the
// Protected Users group, which exposes their credentials to theft
// techniques the group is designed to block (not an audit control).
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
	var credentialTheftExposure []types.User
	for _, admin := range adminsNotProtected {
		if admin.PasswordLastSet.IsZero() || admin.PasswordLastSet.Before(sixMonthsAgo) {
			credentialTheftExposure = append(credentialTheftExposure, admin)
		}
	}

	finding := types.Finding{
		Type:     d.ID(),
		Severity: types.SeverityHigh,
		Category: string(d.Category()),
		Title:    "Privileged Accounts Not Protected Against Credential Theft",
		// Protected Users protects against credential theft (blocks NTLM,
		// disables weak Kerberos encryption types, prevents credential
		// caching and delegation) - it does not enable or disable auditing.
		// https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group
		Description: "Privileged accounts are not members of the Protected Users group, leaving their credentials exposed to theft techniques (NTLM authentication, weak Kerberos encryption, credential caching) that the group is designed to block. Accounts with old passwords widen this exposure window.",
		Count:       len(credentialTheftExposure),
	}

	if len(credentialTheftExposure) > 0 {
		if data.IncludeDetails {
			finding.AffectedEntities = helpers.ToAffectedUserEntities(credentialTheftExposure)
		}
		finding.Details = map[string]interface{}{
			"totalAdmins":            len(adminUsers),
			"adminsNotProtected":     len(adminsNotProtected),
			"adminsWithOldPasswords": len(credentialTheftExposure),
			"recommendation":         "Add admin accounts to the Protected Users group and enforce regular password rotation.",
			"risks": []string{
				"Credentials can be authenticated via NTLM or weak Kerberos encryption types",
				"Credentials may be cached locally and extracted from memory",
				"Long-unrotated passwords widen the window for credential theft",
			},
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewAdminAuditBypassDetector())
}
