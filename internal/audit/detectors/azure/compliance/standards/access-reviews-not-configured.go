package standards

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

const (
	AZ_ACCESS_REVIEWS_NOT_CONFIGURED = "AZ_ACCESS_REVIEWS_NOT_CONFIGURED"
)

type AccessReviewsNotConfiguredDetector struct {
	audit.BaseDetector
}

func NewAccessReviewsNotConfiguredDetector() *AccessReviewsNotConfiguredDetector {
	return &AccessReviewsNotConfiguredDetector{
		BaseDetector: audit.NewBaseDetector(
			AZ_ACCESS_REVIEWS_NOT_CONFIGURED,
			audit.CategoryAzureCompliance,
		),
	}
}

// B_158/T_058 — used to fire unconditionally. data.AzureAccessReviewsProbed
// (v3.1.38 §1, GetAccessReviewDefinitionsCount against
// /identityGovernance/accessReviews/definitions) distinguishes "the endpoint
// couldn't be probed" from "probed and genuinely zero" — only the latter is a
// real finding.
//
// B_075/T_069 — "couldn't probe" and "probed, all clear" used to collapse
// into the same silent nil, so a report reader could not tell them apart.
// Same fix as risk-protection/signin-events.incompleteStreamFinding: an
// Info-severity finding when the probe never happened, visible in the
// report and zero-weight in the score, instead of a compliance verdict this
// detector never actually reached.
func (d *AccessReviewsNotConfiguredDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	if !data.AzureAccessReviewsProbed {
		return []types.Finding{{
			Type:     d.ID(),
			Severity: types.SeverityInfo,
			Category: string(d.Category()),
			Title:    "Access Reviews Not Configured — not determinable (data not probed)",
			Description: "This check was NOT performed: the access reviews endpoint " +
				"(/identityGovernance/accessReviews/definitions) was never probed this audit " +
				"(missing scope, or the run failed before this collection step — see audit.warnings). " +
				"This is not a compliance verdict either way.",
			Count: 1,
		}}
	}
	if data.AzureAccessReviewsCount > 0 {
		return nil
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "Access Reviews Not Configured",
		Description: "No access review definitions found for guest users or privileged roles.",
		Count:       1,
	}

	if data.IncludeDetails {
		finding.AffectedEntities = []types.AffectedEntity{
			{
				Type:        "tenant",
				DN:          "tenant",
				Name:        "Azure AD Tenant",
				Description: "Access reviews should be configured for guest users and privileged roles",
			},
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewAccessReviewsNotConfiguredDetector())
}
