package privileged

import (
	"context"
	"fmt"
	"time"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// AdminNativeRecentLogonDetector flags when the built-in Administrator account
// (RID 500) has been used recently. The native admin should be reserved for
// emergency/break-glass use; regular use increases exposure.
// Matches PingCastle P-AdminLogin.
type AdminNativeRecentLogonDetector struct {
	audit.BaseDetector
}

func NewAdminNativeRecentLogonDetector() *AdminNativeRecentLogonDetector {
	return &AdminNativeRecentLogonDetector{
		BaseDetector: audit.NewBaseDetector("ADMIN_NATIVE_RECENT_LOGON", audit.CategoryAccounts),
	}
}

const adminRecentThreshold = 30 * 24 * time.Hour // 30 days

func (d *AdminNativeRecentLogonDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	count := 0
	daysAgo := -1

	if data.DomainInfo != nil && !data.DomainInfo.AdminLastLoginDate.IsZero() {
		// T_064/B_055 — measured against data.Now (the audit's own reference
		// time), not time.Now(). AdminLastLoginDate comes from a fixed LDAP
		// attribute; replaying a frozen capture against the live wall clock
		// made this detector's result drift purely with the calendar date it
		// happened to be replayed on, independent of any real change in the
		// underlying (immutable) capture.
		age := data.Now.Sub(data.DomainInfo.AdminLastLoginDate)
		daysAgo = int(age.Hours() / 24)
		if age < adminRecentThreshold {
			count = 1
		}
	}

	finding := types.Finding{
		Type:     d.ID(),
		Severity: types.SeverityMedium,
		Category: string(d.Category()),
		Title:    "Built-in Administrator Account Used Recently",
		Description: fmt.Sprintf("The native Administrator account (RID 500) was last used %d day(s) ago. "+
			"This account should be reserved for break-glass scenarios. Routine use increases the "+
			"risk of credential exposure.", daysAgo),
		Count: count,
	}

	if count > 0 {
		finding.Details = map[string]interface{}{
			"daysAgo":        daysAgo,
			"recommendation": "Disable the built-in Administrator account for daily use. Create named admin accounts with MFA and audit logging.",
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewAdminNativeRecentLogonDetector())
}
