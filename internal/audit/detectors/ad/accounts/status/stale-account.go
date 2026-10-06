package status

import (
	"context"
	"time"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// lastLogonTimestamp is replicated (unlike lastLogon, which is
// per-DC and never replicated) but lags real activity by up to its sync
// interval, 14 days by default. Widening the cutoff by that much avoids
// flagging an account as stale purely because of replication lag rather
// than actual inactivity.
const staleAccountReplicationTolerance = 14 * 24 * time.Hour

// StaleAccountDetector detects stale accounts (180+ days inactive)
type StaleAccountDetector struct {
	audit.BaseDetector
}

// NewStaleAccountDetector creates a new detector
func NewStaleAccountDetector() *StaleAccountDetector {
	return &StaleAccountDetector{
		BaseDetector: audit.NewBaseDetector("STALE_ACCOUNT", audit.CategoryAccounts),
	}
}

// Detect executes the detection
func (d *StaleAccountDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.User

	now := data.Now
	cutoff := now.AddDate(0, -6, 0).Add(-staleAccountReplicationTolerance)

	for _, u := range data.Users {
		// Must be enabled
		if u.Disabled {
			continue
		}
		// lastLogonTimestamp (replicated) instead of lastLogon (per-DC, never
		// replicated) - see staleAccountReplicationTolerance above.
		if u.LastLogonTimestamp.IsZero() {
			continue
		}
		if u.LastLogonTimestamp.Before(cutoff) {
			affected = append(affected, u)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "Stale Account (180+ Days)",
		Description: "Enabled user accounts inactive for 180+ days. Stale accounts increase attack surface and should be reviewed.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewStaleAccountDetector())
}
