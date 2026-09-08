package trusts

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// BidirectionalDetector detects bidirectional trust relationships
type BidirectionalDetector struct {
	audit.BaseDetector
}

// NewBidirectionalDetector creates a new detector
func NewBidirectionalDetector() *BidirectionalDetector {
	return &BidirectionalDetector{
		BaseDetector: audit.NewBaseDetector("TRUST_BIDIRECTIONAL", audit.CategoryTrusts),
	}
}

// Detect executes the detection
func (d *BidirectionalDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affectedNames []string

	for _, t := range data.Trusts {
		// Skip intra-forest trusts (parent-child are always bidirectional by design)
		if t.TrustType == "Parent" || t.TrustType == "Child" {
			continue
		}

		// Check for bidirectional trusts
		if t.TrustDirection == "Bidirectional" {
			affectedNames = append(affectedNames, t.TargetDomain)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "Bidirectional Trust Relationship",
		Description: "Two-way trust allows authentication in both directions, increasing the attack surface. A compromise in either domain can lead to lateral movement to the other.",
		Count:       len(affectedNames),
	}

	if len(affectedNames) > 0 {
		finding.Details = map[string]interface{}{
			"recommendation": "Consider using one-way trusts where possible. Implement selective authentication.",
		}
	}

	if data.IncludeDetails && len(affectedNames) > 0 {
		entities := make([]types.AffectedEntity, len(affectedNames))
		for i, name := range affectedNames {
			entities[i] = types.AffectedEntity{
				Type:        "trust",
				DisplayName: name,
			}
		}
		finding.AffectedEntities = entities
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewBidirectionalDetector())
}
