package standards

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

const (
	AZ_NO_TERMS_OF_USE = "AZ_NO_TERMS_OF_USE"
)

type NoTermsOfUseDetector struct {
	audit.BaseDetector
}

func NewNoTermsOfUseDetector() *NoTermsOfUseDetector {
	return &NoTermsOfUseDetector{
		BaseDetector: audit.NewBaseDetector(
			AZ_NO_TERMS_OF_USE,
			audit.CategoryAzureCompliance,
		),
	}
}

// B_158/T_058 — used to fire unconditionally. data.AzureTermsOfUseProbed
// (GetTermsOfUseAgreementsCount against
// /identityGovernance/termsOfUse/agreements) distinguishes "couldn't probe"
// from "probed and genuinely zero agreements".
//
// B_075/T_069 — "couldn't probe" and "probed, all clear" used to collapse
// into the same silent nil. Same fix as the sibling governance checks: an
// Info-severity finding when the probe never happened, visible in the
// report, zero-weight in the score.
func (d *NoTermsOfUseDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	if !data.AzureTermsOfUseProbed {
		return []types.Finding{{
			Type:     d.ID(),
			Severity: types.SeverityInfo,
			Category: string(d.Category()),
			Title:    "No Terms of Use Configured — not determinable (data not probed)",
			Description: "This check was NOT performed: the Terms of Use endpoint " +
				"(/identityGovernance/termsOfUse/agreements) was never probed this audit (missing " +
				"scope, or the run failed before this collection step — see audit.warnings). This is " +
				"not a compliance verdict either way.",
			Count: 1,
		}}
	}
	if data.AzureTermsOfUseCount > 0 {
		return nil
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityLow,
		Category:    string(d.Category()),
		Title:       "No Terms of Use Configured",
		Description: "No Terms of Use agreements configured (referenceable from Conditional Access policies).",
		Count:       1,
	}

	if data.IncludeDetails {
		finding.AffectedEntities = []types.AffectedEntity{
			{
				Type:        "tenant",
				DN:          "tenant",
				Name:        "Azure AD Tenant",
				Description: "Terms of Use policies should be configured in Conditional Access",
			},
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewNoTermsOfUseDetector())
}
