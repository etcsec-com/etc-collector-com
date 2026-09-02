package status

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// DCInactiveDetector flags domain controllers whose last logon timestamp is
// older than 90 days, suggesting replication or decommissioning issues.
// Matches PingCastle S-DC-Inactive.
type DCInactiveDetector struct {
	audit.BaseDetector
}

func NewDCInactiveDetector() *DCInactiveDetector {
	return &DCInactiveDetector{
		BaseDetector: audit.NewBaseDetector("DC_INACTIVE", audit.CategoryComputers),
	}
}

func (d *DCInactiveDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	cutoff := data.Now.AddDate(0, 0, -90)
	var affected []types.Computer

	for i := range data.DomainControllers {
		dc := &data.DomainControllers[i]
		last := dc.LastLogonTimestamp
		if last.IsZero() {
			last = dc.LastLogon
		}
		if last.IsZero() || last.Before(cutoff) {
			affected = append(affected, *dc)
		}
	}

	finding := types.Finding{
		Type:     d.ID(),
		Severity: types.SeverityHigh,
		Category: string(d.Category()),
		Title:    "Inactive Domain Controller",
		Description: "One or more domain controllers have not authenticated in over 90 days. " +
			"This may indicate a failed decommission, a replication break, or a rogue DC object. " +
			"An inactive DC object can be hijacked to re-introduce a compromised machine.",
		Count: len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedComputerEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewDCInactiveDetector())
}
