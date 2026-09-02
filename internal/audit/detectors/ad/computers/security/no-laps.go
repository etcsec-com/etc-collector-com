package security

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// NoLapsDetector checks for computers without LAPS deployed
type NoLapsDetector struct {
	audit.BaseDetector
}

// NewNoLapsDetector creates a new detector
func NewNoLapsDetector() *NoLapsDetector {
	return &NoLapsDetector{
		BaseDetector: audit.NewBaseDetector("COMPUTER_NO_LAPS", audit.CategoryComputers),
	}
}

// Detect executes the detection
func (d *NoLapsDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// SERVER_TRUST_ACCOUNT flag for Domain Controllers
	const serverTrustAccount = 0x2000

	// Check if any computer has LAPS attributes (indicates schema is extended)
	var hasLegacyLapsSchema, hasWindowsLapsSchema bool
	var withLegacyLaps, withWindowsLaps int

	var affected []types.Computer

	for _, c := range data.Computers {
		// Only check enabled computers
		if c.Disabled {
			continue
		}

		// Skip Domain Controllers (they don't use LAPS)
		if (c.UserAccountControl & serverTrustAccount) != 0 {
			continue
		}

		// Track if schema attributes exist
		if c.HasLegacyLAPS {
			hasLegacyLapsSchema = true
			withLegacyLaps++
		}
		if c.HasWindowsLAPS {
			hasWindowsLapsSchema = true
			withWindowsLaps++
		}

		// No LAPS if neither legacy nor Windows LAPS is configured
		if !c.HasLegacyLAPS && !c.HasWindowsLAPS {
			affected = append(affected, c)
		}
	}

	// Determine severity based on schema availability
	schemaExtended := hasLegacyLapsSchema || hasWindowsLapsSchema

	severity := types.SeverityHigh
	title := "Computer No LAPS"
	description := "Computer without LAPS deployed. Shared/static local admin passwords across workstations."

	if !schemaExtended && len(affected) > 0 {
		severity = types.SeverityCritical
		title = "LAPS Not Deployed (Schema Not Extended)"
		description = "LAPS schema is not extended in Active Directory. ALL local admin passwords are unmanaged and likely shared across computers."
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    severity,
		Category:    string(d.Category()),
		Title:       title,
		Description: description,
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedComputerEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewNoLapsDetector())
}
