package security

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// SMBSigningDisabledDetector checks for computers with SMB signing disabled
type SMBSigningDisabledDetector struct {
	audit.BaseDetector
}

// NewSMBSigningDisabledDetector creates a new detector
func NewSMBSigningDisabledDetector() *SMBSigningDisabledDetector {
	return &SMBSigningDisabledDetector{
		BaseDetector: audit.NewBaseDetector("COMPUTER_SMB_SIGNING_DISABLED", audit.CategoryComputers),
	}
}

// Detect executes the detection
func (d *SMBSigningDisabledDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.Computer

	for _, c := range data.Computers {
		if c.SMBSigningDisabled {
			affected = append(affected, c)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityLow,
		Category:    string(d.Category()),
		Title:       "Computer SMB Signing Disabled",
		Description: "Computer with SMB signing disabled. Vulnerable to SMB relay attacks (informational finding).",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedComputerEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewSMBSigningDisabledDetector())
}
