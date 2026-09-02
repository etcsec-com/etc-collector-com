package response

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

const (
	RISK_USERS_NOT_REMEDIATED = "RISK_USERS_NOT_REMEDIATED"
)

type RiskyUsersNotRemediatedDetector struct {
	audit.BaseDetector
}

func NewRiskyUsersNotRemediatedDetector() *RiskyUsersNotRemediatedDetector {
	return &RiskyUsersNotRemediatedDetector{
		BaseDetector: audit.NewBaseDetector(
			RISK_USERS_NOT_REMEDIATED,
			audit.CategoryRiskProtection,
		),
	}
}

func (d *RiskyUsersNotRemediatedDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityCritical,
		Category:    string(d.Category()),
		Title:       "Risky Users Not Remediated",
		Description: "Users flagged as risky have not been remediated or dismissed. Active risks indicate compromised accounts.",
		Count:       0,
	}

	var riskyUsers []types.RiskyUser

	for _, ru := range data.AzureRiskyUsers {
		if ru.RiskState == "atRisk" || ru.RiskState == "confirmedCompromised" {
			finding.Count++
			riskyUsers = append(riskyUsers, ru)
		}
	}

	if finding.Count > 0 && data.IncludeDetails {
		finding.AffectedEntities = helpers.ToAffectedRiskyUserEntities(riskyUsers)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewRiskyUsersNotRemediatedDetector())
}
