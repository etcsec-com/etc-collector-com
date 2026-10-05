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
		Description: "Domain controllers where the Print Spooler RPC pipe (\\PIPE\\spoolss) was confirmed reachable are vulnerable to PrintNightmare (CVE-2021-34527) and PrinterBug attacks for credential relay. SMB (port 445) being open is not evidence by itself: it is open on every domain controller regardless of spooler state.",
	}

	if data.NetworkProbes == nil {
		return []types.Finding{finding}
	}

	var affected []string
	var notDetermined []string
	for _, result := range data.NetworkProbes.SpoolerResults {
		switch {
		case result.SpoolerRunning:
			affected = append(affected, result.DCHostname)
		case !result.Determined:
			notDetermined = append(notDetermined, result.DCHostname)
		}
	}

	finding.Count = len(affected)
	if data.IncludeDetails && (len(affected) > 0 || len(notDetermined) > 0) {
		details := map[string]interface{}{
			"recommendation": "Disable the Print Spooler service on all domain controllers: Stop-Service Spooler; Set-Service Spooler -StartupType Disabled",
		}
		if len(affected) > 0 {
			details["affectedDCs"] = affected
		}
		if len(notDetermined) > 0 {
			details["notDetermined"] = notDetermined
			details["notDeterminedReason"] = "domain controller hostname could not be resolved, or SMB (port 445) was reachable but the spoolss RPC pipe could not be verified without an authenticated SMB session"
		}
		finding.Details = details
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewDcSpoolerDetector())
}
