package status

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// AccountExpireSoonDetector detects accounts expiring soon
type AccountExpireSoonDetector struct {
	audit.BaseDetector
}

// NewAccountExpireSoonDetector creates a new detector
func NewAccountExpireSoonDetector() *AccountExpireSoonDetector {
	return &AccountExpireSoonDetector{
		BaseDetector: audit.NewBaseDetector("ACCOUNT_EXPIRE_SOON", audit.CategoryAccounts),
	}
}

// Detect executes the detection
func (d *AccountExpireSoonDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.User

	now := data.Now
	// The accountExpires attribute itself is well documented (MS-ADA1 §2.13,
	// learn.microsoft.com/en-us/openspecs/windows_protocols/ms-ada1/130eca00-3894-4501-b661-9714e2783c64:
	// a FILETIME; 0 or 9223372036854775807 both mean "never expires", see
	// parseFileTime in internal/providers/ldap/parser.go). But neither that
	// spec nor Microsoft Learn's AD hardening guidance, ANSSI, nor the CIS
	// benchmark prescribes a specific "expiring soon" warning window - unlike
	// e.g. GPO password-expiry notifications, there is no referenced number
	// of days for account-expiration lookahead. 30 days is a product
	// benchmark chosen by this tool, not a requirement from any of those
	// sources - treat it as a tunable heuristic, not a compliance threshold.
	thirtyDaysFromNow := now.AddDate(0, 0, 30)

	for _, u := range data.Users {
		// Must be enabled
		if u.Disabled {
			continue
		}
		// Check accountExpires
		if u.AccountExpires.IsZero() {
			continue // Never expires
		}
		// Expiring within 30 days but not already expired
		if u.AccountExpires.After(now) && u.AccountExpires.Before(thirtyDaysFromNow) {
			affected = append(affected, u)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "Account Expiring Soon",
		Description: "User accounts set to expire within the next 30 days. Review if these expirations are intentional or if accounts need to be extended.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewAccountExpireSoonDetector())
}
