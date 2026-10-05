package governance

import (
	"context"
	"time"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// StaleGuest90Detector checks for stale guest accounts (90+ days)
type StaleGuest90Detector struct {
	audit.BaseDetector
}

// NewStaleGuest90Detector creates a new detector
func NewStaleGuest90Detector() *StaleGuest90Detector {
	return &StaleGuest90Detector{
		BaseDetector: audit.NewBaseDetector("GUEST_STALE_90_DAYS", audit.CategoryGuestExternal),
	}
}

// Detect executes the detection
func (d *StaleGuest90Detector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.User
	threshold := data.Now.AddDate(0, 0, -90)

	for _, user := range data.Users {
		if isGuestUser(user) && user.Enabled() {
			// Use Azure sign-in timestamps (primary) with AD fallback
			var lastActivity time.Time
			if user.AzureLastSignInDateTime != nil && !user.AzureLastSignInDateTime.IsZero() {
				lastActivity = *user.AzureLastSignInDateTime
			}
			if user.AzureLastNonInteractiveSignInDateTime != nil && !user.AzureLastNonInteractiveSignInDateTime.IsZero() {
				if lastActivity.IsZero() || user.AzureLastNonInteractiveSignInDateTime.After(lastActivity) {
					lastActivity = *user.AzureLastNonInteractiveSignInDateTime
				}
			}
			// AD fallback
			if lastActivity.IsZero() {
				if !user.LastLogon.IsZero() {
					lastActivity = user.LastLogon
				} else if !user.LastLogonTimestamp.IsZero() {
					lastActivity = user.LastLogonTimestamp
				}
			}
			if !lastActivity.IsZero() && lastActivity.Before(threshold) {
				affected = append(affected, user)
			}
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "Stale Guest Accounts (90+ Days)",
		Description: "Guest user accounts inactive for 90+ days should be reviewed and removed.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewStaleGuest90Detector())
}
