package lifecycle

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

const (
	IDDisabledNotBlocked       = "USER_DISABLED_NOT_BLOCKED"
	CategoryDisabledNotBlocked = audit.CategoryIdentity
)

// DisabledNotBlockedDetector checks for disabled users not blocked from sign-in
type DisabledNotBlockedDetector struct {
	audit.BaseDetector
}

// NewUserDisabledNotBlockedDetector creates a new disabled not blocked detector
func NewUserDisabledNotBlockedDetector() *DisabledNotBlockedDetector {
	return &DisabledNotBlockedDetector{
		BaseDetector: audit.NewBaseDetector(IDDisabledNotBlocked, CategoryDisabledNotBlocked),
	}
}

// Detect finds disabled user accounts that may still have active sessions
func (d *DisabledNotBlockedDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	finding := types.Finding{
		Type:        IDDisabledNotBlocked,
		Severity:    types.SeverityMedium,
		Category:    string(CategoryDisabledNotBlocked),
		Title:       "Disabled Users Not Blocked from Sign-In",
		Description: "User accounts are disabled but may still have active sessions or tokens.",
		Count:       0,
	}

	var affected []types.User

	for _, user := range data.Users {
		if user.Disabled {
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
	audit.MustRegister(NewUserDisabledNotBlockedDetector())
}
