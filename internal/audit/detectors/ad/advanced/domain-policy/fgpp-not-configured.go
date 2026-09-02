package domainpolicy

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// FGPPNotConfiguredDetector detects the absence of Fine-Grained Password Policies
type FGPPNotConfiguredDetector struct {
	audit.BaseDetector
}

// NewFGPPNotConfiguredDetector creates a new detector
func NewFGPPNotConfiguredDetector() *FGPPNotConfiguredDetector {
	return &FGPPNotConfiguredDetector{
		BaseDetector: audit.NewBaseDetector("FGPP_NOT_CONFIGURED", audit.CategoryAdvanced),
	}
}

// Detect executes the detection
func (d *FGPPNotConfiguredDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "Fine-Grained Password Policy Not Configured",
		Description: "No Fine-Grained Password Policy (PSO) is configured. Privileged accounts (Tier 0) should have a dedicated FGPP with stricter requirements than the domain default policy.",
	}

	if len(data.FGPPs) == 0 {
		finding.Count = 1
		finding.Details = map[string]interface{}{
			"recommendation": "Create a FGPP for privileged accounts with minimum 20 characters, 0 max age, and 48 history.",
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewFGPPNotConfiguredDetector())
}
