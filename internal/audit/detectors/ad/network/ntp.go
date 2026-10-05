package network

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// NtpDetector checks for NTP configuration issues
type NtpDetector struct {
	audit.BaseDetector
}

// NewNtpDetector creates a new detector
func NewNtpDetector() *NtpDetector {
	return &NtpDetector{
		BaseDetector: audit.NewBaseDetector("NTP_NOT_CONFIGURED", audit.CategoryNetwork),
	}
}

// Detect executes the detection
func (d *NtpDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// PDC Emulator should be the authoritative time source
	// Check if there are multiple DCs (time sync is critical with multiple DCs)
	hasSingleDc := len(data.DomainControllers) <= 1

	count := 0
	if !hasSingleDc {
		count = 1
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityLow,
		Category:    string(d.Category()),
		Title:       "NTP Configuration Review Needed",
		Description: "This check only flags a domain with two or more domain controllers as a reminder to review the time synchronization hierarchy - the PDC Emulator should be the authoritative time source, and clock skew across DCs can cause Kerberos authentication failures. It does not read w32time, any GPO, or any registry value from any DC, and cannot tell whether time sync is actually configured correctly or broken.",
		Count:       count,
		Details: map[string]interface{}{
			"dcCount":        len(data.DomainControllers),
			"recommendation": "Configure PDC Emulator as authoritative time source. Other DCs should sync from PDC.",
		},
	}

	if data.IncludeDetails && !hasSingleDc {
		finding.AffectedEntities = helpers.ToAffectedComputerEntities(data.DomainControllers)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewNtpDetector())
}
