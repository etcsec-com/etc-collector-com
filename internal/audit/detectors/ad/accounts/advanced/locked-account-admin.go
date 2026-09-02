package advanced

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// LockedAccountAdminDetector detects locked admin accounts
type LockedAccountAdminDetector struct {
	audit.BaseDetector
}

// NewLockedAccountAdminDetector creates a new detector
func NewLockedAccountAdminDetector() *LockedAccountAdminDetector {
	return &LockedAccountAdminDetector{
		BaseDetector: audit.NewBaseDetector("LOCKED_ACCOUNT_ADMIN", audit.CategoryAccounts),
	}
}

// Detect executes the detection
func (d *LockedAccountAdminDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.User

	adminGroups := []string{
		"Domain Admins",
		"Enterprise Admins",
		"Schema Admins",
		"Administrators",
		"Account Operators",
		"Server Operators",
		"Backup Operators",
	}

	for _, u := range data.Users {
		if len(u.MemberOf) == 0 {
			continue
		}

		// Check if account is locked (UAC flag 0x10)
		isLocked := u.LockedOut || (u.UserAccountControl&0x10) != 0

		if !isLocked {
			continue
		}

		// Check if in admin group
		if helpers.IsInAnyGroup(u.MemberOf, adminGroups) {
			affected = append(affected, u)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "Locked Administrative Account",
		Description: "Administrative accounts that are currently locked out. May indicate password spray attacks or compromised credential attempts.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
		finding.Details = map[string]interface{}{
			"recommendation": "Investigate why these admin accounts are locked. Check security logs for failed authentication attempts.",
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewLockedAccountAdminDetector())
}
