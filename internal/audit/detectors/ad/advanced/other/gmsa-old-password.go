package other

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// GMSAOldPasswordDetector detects gMSA accounts with passwords older than 60 days
type GMSAOldPasswordDetector struct {
	audit.BaseDetector
}

// NewGMSAOldPasswordDetector creates a new detector
func NewGMSAOldPasswordDetector() *GMSAOldPasswordDetector {
	return &GMSAOldPasswordDetector{
		BaseDetector: audit.NewBaseDetector("GMSA_OLD_PASSWORD", audit.CategoryAdvanced),
	}
}

// Detect executes the detection
func (d *GMSAOldPasswordDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	now := data.Now
	sixtyDaysAgo := now.AddDate(0, 0, -60)

	var affected []types.User

	for _, user := range data.Users {
		if !user.IsGMSA {
			continue
		}

		if user.PasswordLastSet.IsZero() {
			continue
		}

		if user.PasswordLastSet.Before(sixtyDaysAgo) {
			affected = append(affected, user)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "gMSA Objects with Old Passwords",
		Description: "Group Managed Service Accounts with passwords that haven't rotated in over 60 days. gMSA passwords should auto-rotate per their managed password interval.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewGMSAOldPasswordDetector())
}
