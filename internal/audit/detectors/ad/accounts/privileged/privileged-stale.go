package privileged

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// PrivilegedAccountStaleDetector detects stale privileged accounts
type PrivilegedAccountStaleDetector struct {
	audit.BaseDetector
}

// NewPrivilegedAccountStaleDetector creates a new detector
func NewPrivilegedAccountStaleDetector() *PrivilegedAccountStaleDetector {
	return &PrivilegedAccountStaleDetector{
		BaseDetector: audit.NewBaseDetector("PRIVILEGED_ACCOUNT_STALE", audit.CategoryAccounts),
	}
}

// Detect executes the detection
func (d *PrivilegedAccountStaleDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.User

	now := data.Now
	ninetyDaysAgo := now.AddDate(0, 0, -90)

	for _, u := range data.Users {
		if u.Disabled {
			continue
		}

		// Must be privileged
		isPrivileged := u.AdminCount || helpers.IsInAnyGroup(u.MemberOf, helpers.AdminGroups)
		if !isPrivileged {
			continue
		}

		// Check last logon
		lastLogon := u.LastLogonTimestamp
		if lastLogon.IsZero() {
			lastLogon = u.LastLogon
		}

		if lastLogon.IsZero() || lastLogon.Before(ninetyDaysAgo) {
			affected = append(affected, u)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "Stale Privileged Accounts",
		Description: "Privileged accounts inactive for 90+ days. Dormant admin accounts increase attack surface.",
		Count:       len(affected),
		Details: map[string]interface{}{
			"threshold":      "90 days",
			"recommendation": "Review and disable unused privileged accounts",
		},
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewPrivilegedAccountStaleDetector())
}
