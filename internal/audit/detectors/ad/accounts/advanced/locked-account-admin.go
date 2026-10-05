package advanced

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/detectors/ad/privgroups"
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

	// adminGroupSIDSuffixes is the RID-suffix form of the same 7 groups:
	// Domain Admins, Enterprise Admins, Schema Admins,
	// Administrators, Account Operators, Server Operators, Backup
	// Operators - matched by SID, not CN, so a homonym doesn't
	// false-positive and a renamed real group is still caught. All 7
	// suffixes already appear in types.PrivilegedSIDSuffixes.
	adminGroupSIDSuffixes := []string{"-512", "-519", "-518", "-544", "-548", "-549", "-551"}
	adminDNs := privgroups.DNsBySIDSuffix(data, adminGroupSIDSuffixes)

	for _, u := range data.Users {
		if len(u.MemberOf) == 0 {
			continue
		}

		// Check if account is locked via lockoutTime, not the UAC LOCKOUT
		// bit (0x10). Since Windows Server 2003 that bit no longer reflects
		// live lockout state (KB305144); AD stamps lockoutTime with the
		// FILETIME of the lockout event and clears it to 0 on unlock or
		// reset, so it is the authoritative signal and is already collected
		// (internal/providers/ldap/parser.go parses "lockoutTime" into
		// types.User.LockoutTime).
		isLocked := !u.LockoutTime.IsZero() && u.LockoutTime.Year() > 1970

		if !isLocked {
			continue
		}

		// Check if in admin group
		if privgroups.IsMemberOfAny(u.MemberOf, adminDNs) {
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
