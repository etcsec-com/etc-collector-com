package policies

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// NoLegacyAuthBlockDetector checks if any CA policy blocks legacy authentication
type NoLegacyAuthBlockDetector struct {
	audit.BaseDetector
}

// NewNoLegacyAuthBlockDetector creates a new detector
func NewNoLegacyAuthBlockDetector() *NoLegacyAuthBlockDetector {
	return &NoLegacyAuthBlockDetector{
		BaseDetector: audit.NewBaseDetector("CA_NO_LEGACY_AUTH_BLOCK", audit.CategoryConditionalAccess),
	}
}

// Detect executes the detection
func (d *NoLegacyAuthBlockDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	hasLegacyAuthBlock := false

	for _, p := range data.AzureConditionalAccessPolicies {
		if p.State != "enabled" {
			continue
		}

		// Check if policy targets legacy auth protocols
		targetsLegacyAuth := containsStr(p.ClientAppTypes, "exchangeActiveSync") ||
			containsStr(p.ClientAppTypes, "other")

		// Check if it blocks access
		blocks := containsStr(p.GrantControls, "block")

		if targetsLegacyAuth && blocks {
			hasLegacyAuthBlock = true
			break
		}
	}

	count := 0
	if !hasLegacyAuthBlock {
		count = 1
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityCritical,
		Category:    string(d.Category()),
		Title:       "No CA Policy Blocks Legacy Authentication",
		Description: "No CA policy blocks legacy authentication protocols that cannot use MFA.",
		Count:       count,
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewNoLegacyAuthBlockDetector())
}
