package detection

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

const (
	RISK_USER_LOW_THRESHOLD = "RISK_USER_LOW_THRESHOLD"
)

type UserRiskLowThresholdDetector struct {
	audit.BaseDetector
}

func NewUserRiskLowThresholdDetector() *UserRiskLowThresholdDetector {
	return &UserRiskLowThresholdDetector{
		BaseDetector: audit.NewBaseDetector(
			RISK_USER_LOW_THRESHOLD,
			audit.CategoryRiskProtection,
		),
	}
}

func (d *UserRiskLowThresholdDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "User Risk Threshold Too Low",
		Description: "User risk policies should trigger at medium risk or above.",
		Count:       0,
	}

	var lowThresholdPolicies []types.ConditionalAccessPolicy

	for _, policy := range data.AzureConditionalAccessPolicies {
		if policy.State != "enabled" || len(policy.UserRiskLevels) == 0 {
			continue
		}

		hasMedium := false
		hasHigh := false
		for _, level := range policy.UserRiskLevels {
			if level == "medium" {
				hasMedium = true
			}
			if level == "high" {
				hasHigh = true
			}
		}

		// If only high risk is configured (missing medium)
		if hasHigh && !hasMedium {
			finding.Count++
			lowThresholdPolicies = append(lowThresholdPolicies, policy)
		}
	}

	if finding.Count > 0 && data.IncludeDetails {
		finding.AffectedEntities = helpers.ToAffectedCAPolicyEntities(lowThresholdPolicies)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewUserRiskLowThresholdDetector())
}
