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

// Detect executes the detection.
//
// A prior version's Title ("BitLocker Not Detected") and Description
// ("Servers without BitLocker recovery information in AD") falsely claimed
// a detection that does not exist: no ms-FVE-RecoveryInformation child
// object, or any other BitLocker signal, is ever read here (see the TODO
// this replaces). The actual logic is "server computer account, enabled" -
// a plain inventory proxy for "should be manually reviewed for encryption",
// not a finding that BitLocker is absent. Retitled and downgraded from High
// to Info accordingly: this is a review nudge, not a confirmed
// vulnerability. GPO-level enforcement is checked separately and correctly
// by gpo.BitLockerDetector (FVE\RequireDeviceEncryption via GPO registry
// settings), which this detector does not duplicate or supersede.
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

		affected = append(affected, c)
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityInfo,
		Category:    string(d.Category()),
		Title:       "Server BitLocker Status Not Verifiable From AD Metadata",
		Description: "Enabled server computer accounts for which this detector cannot confirm BitLocker status one way or the other - no BitLocker signal is read from AD for individual computers. Flagged for manual review only, not as a confirmed absence of encryption.",
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
