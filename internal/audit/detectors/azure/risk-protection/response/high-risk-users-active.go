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

// Detect flags riskyUser records at "high" risk level that remain "atRisk" or
// "confirmedCompromised".
//
// riskLevel and riskState are read as the exact enums Microsoft Graph
// defines on the riskyUser resource type (learn.microsoft.com/graph/api/resources/riskyuser,
// Properties table): riskLevel - low, medium, high, hidden, none,
// unknownFutureValue; riskState - none, confirmedSafe, remediated,
// dismissed, atRisk, confirmedCompromised, unknownFutureValue. The values
// checked here ("high" / "atRisk", "confirmedCompromised") match the source
// exactly; no invented threshold is involved.
//
// Empirical confirmation status: not observed firing on the tenant this
// detector was audited against - that tenant had zero riskyUser records at
// riskLevel=high during the audit window, so the "at-risk high-risk user"
// branch of this logic has not been seen live. That is a fact about the
// tenant's state at audit time, not a flaw in the code: the enum values and
// the read path are confirmed correct against the source above.
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
