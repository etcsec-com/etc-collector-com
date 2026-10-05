package lifecycle

import (
	"context"
	"time"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

const (
	ID       = "USER_STALE_90_DAYS"
	Category = audit.CategoryIdentity
)

// UserStale90DaysDetector checks for stale user accounts
type UserStale90DaysDetector struct {
	audit.BaseDetector
}

// NewUserStale90DaysDetector creates a new stale user detector
func NewUserStale90DaysDetector() *UserStale90DaysDetector {
	return &UserStale90DaysDetector{
		BaseDetector: audit.NewBaseDetector(ID, Category),
	}
}

// Detect finds user accounts with no sign-in activity for 90+ days
func (d *UserStale90DaysDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	finding := types.Finding{
		Type:        ID,
		Severity:    types.SeverityHigh,
		Category:    string(Category),
		Title:       "Stale User Accounts (90+ Days)",
		Description: "User accounts with no sign-in activity for 90+ days. Stale accounts increase attack surface.",
		Count:       0,
	}

	var affected []types.User
	now := data.Now
	threshold := now.AddDate(0, 0, -90)

	for _, user := range data.Users {
		if user.Disabled {
			continue
		}

		// Use Azure sign-in timestamps (not AD on-prem LastLogon)
		var lastActivity time.Time
		if user.AzureLastSignInDateTime != nil && !user.AzureLastSignInDateTime.IsZero() {
			lastActivity = *user.AzureLastSignInDateTime
		}
		if user.AzureLastNonInteractiveSignInDateTime != nil && !user.AzureLastNonInteractiveSignInDateTime.IsZero() {
			if lastActivity.IsZero() || user.AzureLastNonInteractiveSignInDateTime.After(lastActivity) {
				lastActivity = *user.AzureLastNonInteractiveSignInDateTime
			}
		}

		if !lastActivity.IsZero() && lastActivity.Before(threshold) {
			affected = append(affected, user)
		}
	}

	finding.Count = len(affected)

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewUserStale90DaysDetector())
}
