package delegation

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// RbcdDetector checks for computers with RBCD configured
type RbcdDetector struct {
	audit.BaseDetector
}

// NewRbcdDetector creates a new detector
func NewRbcdDetector() *RbcdDetector {
	return &RbcdDetector{
		BaseDetector: audit.NewBaseDetector("COMPUTER_RBCD", audit.CategoryComputers),
	}
}

// Detect executes the detection
func (d *RbcdDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.Computer

	for _, c := range data.Computers {
		// Check that msDS-AllowedToActOnBehalfOfOtherIdentity attribute exists and is not empty
		if len(c.AllowedToActOnBehalfOfOtherIdentity) > 0 {
			affected = append(affected, c)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityCritical,
		Category:    string(d.Category()),
		Title:       "Computer RBCD",
		Description: "Computer with Resource-Based Constrained Delegation. Enables privilege escalation via RBCD attack.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedComputerEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewRbcdDetector())
}
