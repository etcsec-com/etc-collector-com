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

// Detect executes the detection.
//
// gMSA objects can never appear in data.Users - GetUsers
// filters (objectCategory=person), and a gMSA's objectCategory is
// ms-DS-Group-Managed-Service-Account, never "person". A gMSA does inherit
// "computer" in the AD schema, so it lands in data.Computers instead (see
// parseComputer's IsGMSA, set from the objectClass list). Read from there.
func (d *GMSAOldPasswordDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	now := data.Now
	sixtyDaysAgo := now.AddDate(0, 0, -60)

	var affected []types.Computer

	for _, computer := range data.Computers {
		if !computer.IsGMSA {
			continue
		}

		if computer.PasswordLastSet.IsZero() {
			continue
		}

		if computer.PasswordLastSet.Before(sixtyDaysAgo) {
			affected = append(affected, computer)
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
		finding.AffectedEntities = helpers.ToAffectedComputerEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewGMSAOldPasswordDetector())
}
