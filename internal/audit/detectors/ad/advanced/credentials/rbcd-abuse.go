package credentials

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// RBCDAbuseDetector detects RBCD abuse configurations
type RBCDAbuseDetector struct {
	audit.BaseDetector
}

// NewRBCDAbuseDetector creates a new detector
func NewRBCDAbuseDetector() *RBCDAbuseDetector {
	return &RBCDAbuseDetector{
		BaseDetector: audit.NewBaseDetector("RBCD_ABUSE", audit.CategoryAdvanced),
	}
}

// Detect executes the detection
func (d *RBCDAbuseDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affectedComputers []types.Computer

	// Check computers for RBCD configuration
	for _, c := range data.Computers {
		// Check msDS-AllowedToActOnBehalfOfOtherIdentity attribute
		if len(c.AllowedToActOnBehalfOfOtherIdentity) > 0 {
			affectedComputers = append(affectedComputers, c)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityCritical,
		Category:    string(d.Category()),
		Title:       "RBCD Abuse",
		Description: "Computers with msDS-AllowedToActOnBehalfOfOtherIdentity configured. This enables privilege escalation via resource-based constrained delegation attacks.",
		Count:       len(affectedComputers),
	}

	if data.IncludeDetails && len(affectedComputers) > 0 {
		finding.AffectedEntities = helpers.ToAffectedComputerEntities(affectedComputers)
		finding.Details = map[string]interface{}{
			"recommendation": "Review and remove unnecessary RBCD configurations. This attribute should only be set when resource-based constrained delegation is intentionally configured.",
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewRBCDAbuseDetector())
}
