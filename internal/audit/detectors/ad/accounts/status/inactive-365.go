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
// flagging an account as inactive purely because of replication lag rather
// than actual inactivity.
const inactive365ReplicationTolerance = 14 * 24 * time.Hour

// Inactive365Detector detects accounts inactive for 365+ days
type Inactive365Detector struct {
	audit.BaseDetector
}

// NewInactive365Detector creates a new detector
func NewInactive365Detector() *Inactive365Detector {
	return &Inactive365Detector{
		BaseDetector: audit.NewBaseDetector("INACTIVE_365_DAYS", audit.CategoryAccounts),
	}
}

// Detect executes the detection
func (d *Inactive365Detector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.User

	now := data.Now
	cutoff := now.AddDate(-1, 0, 0).Add(-inactive365ReplicationTolerance)

	for _, u := range data.Users {
		// lastLogonTimestamp (replicated) instead of lastLogon (per-DC, never
		// replicated) - see inactive365ReplicationTolerance above.
		if u.LastLogonTimestamp.IsZero() {
			continue
		}
		if u.LastLogonTimestamp.Before(cutoff) {
			affected = append(affected, u)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "Inactive 365+ Days",
		Description: "User accounts inactive for 365+ days. Should be disabled or deleted.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewInactive365Detector())
}
