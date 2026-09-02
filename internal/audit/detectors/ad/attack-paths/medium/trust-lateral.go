package medium

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// TrustLateralDetector detects trust relationships enabling lateral movement
type TrustLateralDetector struct {
	audit.BaseDetector
}

// NewTrustLateralDetector creates a new detector
func NewTrustLateralDetector() *TrustLateralDetector {
	return &TrustLateralDetector{
		BaseDetector: audit.NewBaseDetector("PATH_TRUST_LATERAL", audit.CategoryAttackPaths),
	}
}

// Detect executes the detection
func (d *TrustLateralDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var riskyTrusts []types.Trust

	for _, t := range data.Trusts {
		// SID filtering disabled = can inject SIDs from trusted domain
		noSidFiltering := !t.SIDFilteringEnabled
		// Bidirectional = both domains can authenticate to each other
		bidirectional := t.TrustDirectionInt == 3 || t.TrustDirection == "Bidirectional"
		// Forest trust without selective auth
		forestNoSelectiveAuth := t.TrustType == "forest" && !t.SelectiveAuthEnabled

		if noSidFiltering || (bidirectional && forestNoSelectiveAuth) {
			riskyTrusts = append(riskyTrusts, t)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "Trust Relationship Enables Lateral Movement",
		Description: "Domain trusts configured without proper security controls (SID filtering, selective authentication). Compromising trusted domain can lead to this domain.",
		Count:       len(riskyTrusts),
	}

	if data.IncludeDetails && len(riskyTrusts) > 0 {
		var trustDetails []map[string]interface{}
		entities := make([]types.AffectedEntity, len(riskyTrusts))
		for i, t := range riskyTrusts {
			entities[i] = types.AffectedEntity{
				Type:           "trust",
				SAMAccountName: t.Name,
			}
			trustDetails = append(trustDetails, map[string]interface{}{
				"name":          t.Name,
				"direction":     t.Direction,
				"type":          t.TrustType,
				"sidFiltering":  t.SIDFilteringEnabled,
				"selectiveAuth": t.SelectiveAuthEnabled,
			})
		}
		finding.AffectedEntities = entities
		finding.Details = map[string]interface{}{
			"totalTrusts":  len(data.Trusts),
			"riskyTrusts":  trustDetails,
			"attackVector": "Compromise trusted domain → Exploit trust → Access this domain",
			"mitigation":   "Enable SID filtering, use selective authentication for forest trusts",
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewTrustLateralDetector())
}
