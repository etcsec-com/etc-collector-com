package trusts

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// SIDFilteringDisabledDetector detects trusts with SID filtering disabled
type SIDFilteringDisabledDetector struct {
	audit.BaseDetector
}

// NewSIDFilteringDisabledDetector creates a new detector
func NewSIDFilteringDisabledDetector() *SIDFilteringDisabledDetector {
	return &SIDFilteringDisabledDetector{
		BaseDetector: audit.NewBaseDetector("TRUST_SID_FILTERING_DISABLED", audit.CategoryTrusts),
	}
}

// Detect executes the detection.
//
// SID filtering (quarantining) is the mitigation for SID-history injection
// across a trust: Microsoft documents it as a per-external-trust setting
// (trustAttributes bit 0x4, "sIDFilteringQuarantined") and a per-forest-trust
// setting (sIDFilteringForestAware) - never for a parent-child trust inside
// the same forest, where SID filtering is not a meaningful boundary (a
// child domain's Enterprise Admins already administer the whole forest).
// Skipping "Parent"/"Child" TrustType below matches that distinction; no
// code defect was found here. What is missing is empirical confirmation:
// the lab domain carries no external/forest trust at all
// (ad-audit.json: trustsAnalysis.total=0), so this path has never fired
// and no plant/revert has exercised it. Honestly "not observed".
func (d *SIDFilteringDisabledDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affectedNames []string

	for _, t := range data.Trusts {
		// Skip intra-forest trusts (parent-child) - SID filtering not applicable
		if t.TrustType == "Parent" || t.TrustType == "Child" {
			continue
		}

		// Check if SID filtering is disabled
		if !t.SIDFiltering {
			affectedNames = append(affectedNames, t.TargetDomain)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "SID Filtering Disabled on Trust",
		Description: "Trust relationships without SID filtering allow SID history injection attacks, enabling attackers to impersonate any user in the trusted domain.",
		Count:       len(affectedNames),
	}

	if len(affectedNames) > 0 {
		finding.Details = map[string]interface{}{
			"recommendation": "Enable SID filtering (quarantine) on external and forest trusts.",
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
	audit.MustRegister(NewSIDFilteringDisabledDetector())
}
