package delegation

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// ConstrainedDelegationDetector checks for computers with constrained delegation
type ConstrainedDelegationDetector struct {
	audit.BaseDetector
}

// NewConstrainedDelegationDetector creates a new detector
func NewConstrainedDelegationDetector() *ConstrainedDelegationDetector {
	return &ConstrainedDelegationDetector{
		BaseDetector: audit.NewBaseDetector("COMPUTER_CONSTRAINED_DELEGATION", audit.CategoryComputers),
	}
}

// Detect executes the detection
func (d *ConstrainedDelegationDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.Computer

	for _, c := range data.Computers {
		// Check if msDS-AllowedToDelegateTo has any entries
		if len(c.AllowedToDelegateTo) > 0 {
			affected = append(affected, c)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityCritical,
		Category:    string(d.Category()),
		Title:       "Computer Constrained Delegation",
		Description: "Computer with constrained Kerberos delegation. Can impersonate users to specified services.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedComputerEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewConstrainedDelegationDetector())
}
