package network

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
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
		Description: "Time synchronization configuration should be reviewed. The PDC Emulator must be configured as the authoritative time source to prevent Kerberos authentication issues.",
		Count:       count,
		Details: map[string]interface{}{
			"dcCount":        len(data.DomainControllers),
			"recommendation": "Configure PDC Emulator as authoritative time source. Other DCs should sync from PDC.",
		},
	}

	if data.IncludeDetails && !hasSingleDc {
		var dcNames []string
		for _, dc := range data.DomainControllers {
			dcNames = append(dcNames, dc.SAMAccountName)
		}
		finding.AffectedEntities = toAffectedComputerNameEntitiesNtp(dcNames)
	}

	return []types.Finding{finding}
}

// toAffectedComputerNameEntitiesNtp converts a list of computer names to affected entities
func toAffectedComputerNameEntitiesNtp(names []string) []types.AffectedEntity {
	entities := make([]types.AffectedEntity, len(names))
	for i, name := range names {
		entities[i] = types.AffectedEntity{
			Type:           "computer",
			SAMAccountName: name,
		}
	}
	return entities
}

func init() {
	audit.MustRegister(NewNtpDetector())
}
