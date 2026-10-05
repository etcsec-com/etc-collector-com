package response

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

const (
	RISK_LEAKED_CREDENTIALS = "RISK_LEAKED_CREDENTIALS"
)

type LeakedCredentialsNotBlockedDetector struct {
	audit.BaseDetector
}

func NewLeakedCredentialsNotBlockedDetector() *LeakedCredentialsNotBlockedDetector {
	return &LeakedCredentialsNotBlockedDetector{
		BaseDetector: audit.NewBaseDetector(
			RISK_LEAKED_CREDENTIALS,
			audit.CategoryRiskProtection,
		),
	}
}

func (d *LeakedCredentialsNotBlockedDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityCritical,
		Category:    string(d.Category()),
		Title:       "Leaked Credentials Not Blocked",
		Description: "Users with confirmed compromised credentials are not blocked. Immediately remediate these accounts.",
		Count:       0,
	}

	var leakedUsers []types.RiskyUser

	for _, ru := range data.AzureRiskyUsers {
		if ru.RiskState == "confirmedCompromised" {
			finding.Count++
			leakedUsers = append(leakedUsers, ru)
		}
	}

	if finding.Count > 0 && data.IncludeDetails {
		finding.AffectedEntities = helpers.ToAffectedRiskyUserEntities(leakedUsers)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewLeakedCredentialsNotBlockedDetector())
}
