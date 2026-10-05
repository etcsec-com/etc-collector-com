package kerberos

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// AdminAsrepRoastableOnDisabledAccountDetector checks for disabled privileged
// accounts without Kerberos pre-authentication. Split out of
// AdminAsrepRoastableDetector: the KDC rejects the AS-REQ on account status
// before pre-authentication is ever considered, so these accounts are not
// exploitable today - but the bit persists on disk and would matter again
// the moment the account is re-enabled, so it stays reported, at a severity
// that reflects dormancy rather than active risk.
//
// Named ADMIN_ASREP_ROASTABLE_ON_DISABLED_ACCOUNT, not
// ADMIN_ASREP_ROASTABLE_DISABLED: the _DISABLED suffix is reserved elsewhere
// in this catalog for "a protection was turned off", which reads as bad
// news. Naming the population instead of a mechanism state avoids an
// auditor misreading this as the risk itself being off. Same convention as
// ASREP_ROASTING_ON_DISABLED_ACCOUNT (same package, same UAC bit) and
// SENSITIVE_DELEGATION_ON_DISABLED_ACCOUNT.
type AdminAsrepRoastableOnDisabledAccountDetector struct {
	audit.BaseDetector
}

// NewAdminAsrepRoastableOnDisabledAccountDetector creates a new detector
func NewAdminAsrepRoastableOnDisabledAccountDetector() *AdminAsrepRoastableOnDisabledAccountDetector {
	return &AdminAsrepRoastableOnDisabledAccountDetector{
		BaseDetector: audit.NewBaseDetector("ADMIN_ASREP_ROASTABLE_ON_DISABLED_ACCOUNT", audit.CategoryKerberos),
	}
}

// Detect executes the detection
func (d *AdminAsrepRoastableOnDisabledAccountDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.User

	privilegedDNs := privilegedGroupDNsBySIDAsrep(data)

	for _, user := range data.Users {
		if !user.Disabled {
			continue
		}

		if (user.UserAccountControl & types.UACDontRequirePreauth) == 0 {
			continue
		}

		if isMemberOfPrivilegedGroupAsrep(user.MemberOf, privilegedDNs) {
			affected = append(affected, user)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityLow,
		Category:    string(d.Category()),
		Title:       "Privileged Account AS-REP Roastable (Disabled Account)",
		Description: "Disabled privileged accounts (Domain Admins, Domain Controllers, Schema Admins, Enterprise Admins, Key Admins, Enterprise Key Admins, Administrators, Account Operators, Server Operators, Print Operators, Backup Operators) without Kerberos pre-authentication. Not exploitable while disabled - the KDC rejects the AS-REQ on account status first - but the bit remains set and would apply again if the account is re-enabled.",
		Count:       len(affected),
	}

	if len(affected) > 0 {
		if data.IncludeDetails {
			finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
		}
		finding.Details = map[string]interface{}{
			"risk":           "LOW - Not exploitable while the account is disabled; the bit persists and applies again on re-enable",
			"recommendation": "Enable Kerberos pre-authentication before re-enabling this account",
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewAdminAsrepRoastableOnDisabledAccountDetector())
}
