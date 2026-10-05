package response

import (
	"context"
	"fmt"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

const (
	RISK_SIGNINS_NOT_INVESTIGATED = "RISK_SIGNINS_NOT_INVESTIGATED"
)

type RiskySignInsNotInvestigatedDetector struct {
	audit.BaseDetector
}

func NewRiskySignInsNotInvestigatedDetector() *RiskySignInsNotInvestigatedDetector {
	return &RiskySignInsNotInvestigatedDetector{
		BaseDetector: audit.NewBaseDetector(
			RISK_SIGNINS_NOT_INVESTIGATED,
			audit.CategoryRiskProtection,
		),
	}
}

func (d *RiskySignInsNotInvestigatedDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "Risky Sign-Ins Not Investigated",
		Description: "Risk detections have not been investigated. Each detection may indicate an active compromise.",
		Count:       0,
	}

	var riskySignIns []types.AffectedEntity

	for _, si := range data.AzureRiskySignIns {
		if si.RiskState == "atRisk" {
			finding.Count++
			if data.IncludeDetails {
				riskySignIns = append(riskySignIns, types.AffectedEntity{
					Type:        "riskDetection",
					DN:          si.ID,
					Name:        si.UserPrincipalName,
					Description: fmt.Sprintf("Risk: %s, IP: %s", si.RiskLevel, si.IPAddress),
				})
			}
		}
	}

	if finding.Count > 0 && data.IncludeDetails {
		finding.AffectedEntities = riskySignIns
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewRiskySignInsNotInvestigatedDetector())
}
