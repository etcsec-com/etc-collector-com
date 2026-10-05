package delegation

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// DCSyncRightsDetector checks for computers with DCSync rights
type DCSyncRightsDetector struct {
	audit.BaseDetector
}

// NewDCSyncRightsDetector creates a new detector
func NewDCSyncRightsDetector() *DCSyncRightsDetector {
	return &DCSyncRightsDetector{
		BaseDetector: audit.NewBaseDetector("COMPUTER_DCSYNC_RIGHTS", audit.CategoryComputers),
	}
}

// Detect executes the detection
func (d *DCSyncRightsDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.Computer

	for _, c := range data.Computers {
		if c.ReplicationRights {
			affected = append(affected, c)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityCritical,
		Category:    string(d.Category()),
		Title:       "Computer DCSync Rights",
		Description: "Computer with DCSync replication rights. Can extract all domain password hashes.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedComputerEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewDCSyncRightsDetector())
}
