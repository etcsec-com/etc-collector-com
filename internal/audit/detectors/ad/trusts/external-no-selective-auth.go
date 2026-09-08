package trusts

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// ExternalNoSelectiveAuthDetector detects external trusts without selective authentication
type ExternalNoSelectiveAuthDetector struct {
	audit.BaseDetector
}

// NewExternalNoSelectiveAuthDetector creates a new detector
func NewExternalNoSelectiveAuthDetector() *ExternalNoSelectiveAuthDetector {
	return &ExternalNoSelectiveAuthDetector{
		BaseDetector: audit.NewBaseDetector("TRUST_EXTERNAL_NO_SELECTIVE_AUTH", audit.CategoryTrusts),
	}
}

// Detect executes the detection
func (d *ExternalNoSelectiveAuthDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affectedNames []string

	for _, t := range data.Trusts {
		// Only check external trusts (not forest or intra-forest)
		isExternal := t.TrustType == "External"

		if !isExternal {
			continue
		}

		// Check if selective authentication is disabled
		if !t.SelectiveAuth {
			affectedNames = append(affectedNames, t.TargetDomain)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "External Trust Without Selective Authentication",
		Description: "External trust without selective authentication allows any user from the trusted domain to authenticate to any resource in this domain.",
		Count:       len(affectedNames),
	}

	if len(affectedNames) > 0 {
		finding.Details = map[string]interface{}{
			"recommendation": "Enable selective authentication and explicitly grant access only to required resources.",
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
	audit.MustRegister(NewExternalNoSelectiveAuthDetector())
}
