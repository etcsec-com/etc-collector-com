package password

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// NeverExpiresOnDisabledAccountDetector checks for disabled accounts with
// passwords set to never expire. Split out of NeverExpiresDetector: a
// disabled account cannot authenticate, so a never-expiring password on it
// is not usable today - but the configuration survives a re-enable, so it
// stays reported, at a severity that reflects dormancy rather than active
// risk. Same convention as UNCONSTRAINED_DELEGATION_ON_DISABLED_ACCOUNT and
// ASREP_ROASTING_ON_DISABLED_ACCOUNT: the suffix names the population
// covered, not the state of a mechanism - _DISABLED alone is reserved
// elsewhere in this catalog for "a protection was turned off".
type NeverExpiresOnDisabledAccountDetector struct {
	audit.BaseDetector
}

// NewNeverExpiresOnDisabledAccountDetector creates a new detector
func NewNeverExpiresOnDisabledAccountDetector() *NeverExpiresOnDisabledAccountDetector {
	return &NeverExpiresOnDisabledAccountDetector{
		BaseDetector: audit.NewBaseDetector("PASSWORD_NEVER_EXPIRES_ON_DISABLED_ACCOUNT", audit.CategoryPassword),
	}
}

// Detect executes the detection
func (d *NeverExpiresOnDisabledAccountDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.User

	for _, u := range data.Users {
		if !u.Disabled {
			continue
		}
		if (u.UserAccountControl & types.UACDontExpirePassword) != 0 {
			affected = append(affected, u)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityLow,
		Category:    string(d.Category()),
		Title:       "Password Never Expires (Disabled Account)",
		Description: "Disabled user accounts with passwords set to never expire (UAC flag 0x10000). Not usable while disabled, but the configuration survives a re-enable.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewNeverExpiresOnDisabledAccountDetector())
}
