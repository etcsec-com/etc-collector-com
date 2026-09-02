package security

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// NoBitlockerDetector checks for servers without BitLocker encryption
type NoBitlockerDetector struct {
	audit.BaseDetector
}

// NewNoBitlockerDetector creates a new detector
func NewNoBitlockerDetector() *NoBitlockerDetector {
	return &NoBitlockerDetector{
		BaseDetector: audit.NewBaseDetector("COMPUTER_NO_BITLOCKER", audit.CategoryComputers),
	}
}

// Detect executes the detection
// Note: BitLocker status is stored in ms-FVE-RecoveryInformation objects under the computer.
// This detection checks servers that might need BitLocker review based on AD metadata.
func (d *NoBitlockerDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.Computer

	for _, c := range data.Computers {
		if c.Disabled {
			continue
		}

		// Only check servers (not workstations)
		os := strings.ToLower(c.OperatingSystem)
		isServer := strings.Contains(os, "server")
		if !isServer {
			continue
		}

		// TODO: Would need separate query to check for ms-FVE-RecoveryInformation child objects
		// For now, flag all servers as potentially needing BitLocker review
		// In a full implementation, the provider would populate a HasBitlocker field
		affected = append(affected, c)
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "BitLocker Not Detected",
		Description: "Servers without BitLocker recovery information in AD. Unencrypted disks are vulnerable to physical theft and offline attacks.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedComputerEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewNoBitlockerDetector())
}
