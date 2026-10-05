package password

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// NeverExpiresDetector detects accounts with passwords that never expire.
// Scoped to active accounts: a disabled account cannot authenticate, so a
// compromised never-expiring password on it is not usable today - see
// NeverExpiresOnDisabledAccountDetector for the disabled-account claim,
// reported separately at Low.
type NeverExpiresDetector struct {
	audit.BaseDetector
}

// NewNeverExpiresDetector creates a new detector
func NewNeverExpiresDetector() *NeverExpiresDetector {
	return &NeverExpiresDetector{
		BaseDetector: audit.NewBaseDetector("PASSWORD_NEVER_EXPIRES", audit.CategoryPassword),
	}
}

// Detect executes the detection
func (d *NeverExpiresDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.User

	for _, u := range data.Users {
		if u.Disabled {
			continue
		}
		if (u.UserAccountControl & types.UACDontExpirePassword) != 0 {
			affected = append(affected, u)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityCritical,
		Category:    string(d.Category()),
		Title:       "Password Never Expires",
		Description: "Enabled user accounts with passwords set to never expire (UAC flag 0x10000). A compromised password on these accounts remains valid indefinitely.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewNeverExpiresDetector())
}
