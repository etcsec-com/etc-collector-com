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
