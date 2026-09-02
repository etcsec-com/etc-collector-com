package network

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// DcSpoolerDetector detects DCs with Print Spooler service accessible
type DcSpoolerDetector struct {
	audit.BaseDetector
}

// NewDcSpoolerDetector creates a new detector
func NewDcSpoolerDetector() *DcSpoolerDetector {
	return &DcSpoolerDetector{
		BaseDetector: audit.NewBaseDetector("DC_SPOOLER_ACCESSIBLE", audit.CategoryNetwork),
	}
}

// Detect executes the detection
func (d *DcSpoolerDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "Print Spooler Running on Domain Controller",
		Description: "Domain controllers with Print Spooler service running are vulnerable to PrintNightmare (CVE-2021-34527) and PrinterBug attacks for credential relay.",
	}

	if data.NetworkProbes == nil {
		return []types.Finding{finding}
	}

	var affected []string
	for _, result := range data.NetworkProbes.SpoolerResults {
		if result.SpoolerRunning {
			affected = append(affected, result.DCHostname)
		}
	}

	finding.Count = len(affected)
	if data.IncludeDetails && len(affected) > 0 {
		finding.Details = map[string]interface{}{
			"affectedDCs":    affected,
			"recommendation": "Disable the Print Spooler service on all domain controllers: Stop-Service Spooler; Set-Service Spooler -StartupType Disabled",
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewDcSpoolerDetector())
}
