package response

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

const (
	RISK_HIGH_RISK_USERS_ACTIVE = "RISK_HIGH_RISK_USERS_ACTIVE"
)

type HighRiskUsersActiveDetector struct {
	audit.BaseDetector
}

func NewHighRiskUsersActiveDetector() *HighRiskUsersActiveDetector {
	return &HighRiskUsersActiveDetector{
		BaseDetector: audit.NewBaseDetector(
			RISK_HIGH_RISK_USERS_ACTIVE,
			audit.CategoryRiskProtection,
		),
	}
}

func (d *HighRiskUsersActiveDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityCritical,
		Category:    string(d.Category()),
		Title:       "High-Risk Users with Active Accounts",
		Description: "Users flagged as high risk still have active accounts. Investigate and remediate immediately.",
		Count:       0,
	}

	var highRiskUsers []types.RiskyUser

	for _, ru := range data.AzureRiskyUsers {
		if ru.RiskLevel == "high" && (ru.RiskState == "atRisk" || ru.RiskState == "confirmedCompromised") {
			finding.Count++
			highRiskUsers = append(highRiskUsers, ru)
		}
	}

	if finding.Count > 0 && data.IncludeDetails {
		finding.AffectedEntities = helpers.ToAffectedRiskyUserEntities(highRiskUsers)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewHighRiskUsersActiveDetector())
}
