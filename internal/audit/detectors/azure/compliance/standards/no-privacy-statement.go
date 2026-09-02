package standards

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

const (
	AZ_NO_PRIVACY_STATEMENT = "AZ_NO_PRIVACY_STATEMENT"
)

type NoPrivacyStatementDetector struct {
	audit.BaseDetector
}

func NewNoPrivacyStatementDetector() *NoPrivacyStatementDetector {
	return &NoPrivacyStatementDetector{
		BaseDetector: audit.NewBaseDetector(
			AZ_NO_PRIVACY_STATEMENT,
			audit.CategoryAzureCompliance,
		),
	}
}

// B_158/T_058 — used to fire unconditionally. data.AzurePrivacyStatementProbed
// (GetOrganizationPrivacyStatementURL against /organization's privacyProfile)
// distinguishes "couldn't probe" from "probed and genuinely unset".
//
// B_075/T_069 — "couldn't probe" and "probed, configured" used to collapse
// into the same silent nil. Same fix as the sibling governance checks: an
// Info-severity finding when the probe never happened, visible in the
// report, zero-weight in the score.
func (d *NoPrivacyStatementDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	if !data.AzurePrivacyStatementProbed {
		return []types.Finding{{
			Type:     d.ID(),
			Severity: types.SeverityInfo,
			Category: string(d.Category()),
			Title:    "No Privacy Statement Configured — not determinable (data not probed)",
			Description: "This check was NOT performed: /organization's privacyProfile was never " +
				"probed this audit (missing scope, or the run failed before this collection step — " +
				"see audit.warnings). This is not a compliance verdict either way.",
			Count: 1,
		}}
	}
	if data.AzurePrivacyStatementURL != "" {
		return nil
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityLow,
		Category:    string(d.Category()),
		Title:       "No Privacy Statement Configured",
		Description: "Organization privacy statement URL is not configured in Azure AD.",
		Count:       1,
	}

	if data.IncludeDetails {
		finding.AffectedEntities = []types.AffectedEntity{
			{
				Type:        "tenant",
				DN:          "tenant",
				Name:        "Azure AD Tenant",
				Description: "Organization privacy statement URL should be configured",
			},
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewNoPrivacyStatementDetector())
}
