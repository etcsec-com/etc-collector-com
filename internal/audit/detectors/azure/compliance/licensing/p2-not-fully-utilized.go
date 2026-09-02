package licensing

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

const (
	AZ_P2_NOT_FULLY_UTILIZED = "AZ_P2_NOT_FULLY_UTILIZED"
)

type P2NotFullyUtilizedDetector struct {
	audit.BaseDetector
}

func NewP2NotFullyUtilizedDetector() *P2NotFullyUtilizedDetector {
	return &P2NotFullyUtilizedDetector{
		BaseDetector: audit.NewBaseDetector(
			AZ_P2_NOT_FULLY_UTILIZED,
			audit.CategoryAzureCompliance,
		),
	}
}

// B_158/T_058 — used to fire unconditionally on every tenant. Now gated on
// P2 actually being active (data.AzureLicenseTier — a tenant without P2 is
// AZ_NO_P2_LICENSE's territory, not this one) and on at least one concrete,
// already-collected P2 feature signal showing non-adoption: zero PIM-eligible
// role assignments (data.AzurePIMAssignments, nil when the provider couldn't
// probe it — silence in that case, not a guess) or a probed-and-empty access
// review count (data.AzureAccessReviewsProbed/Count).
// B_075/T_069 — when P2 is active but NEITHER underlying signal could be
// probed (data.AzurePIMAssignments nil AND access reviews never probed), the
// original code fell through to the same silent nil as "fully utilized" —
// indistinguishable from a real compliance verdict this detector never
// actually reached. Info-severity finding instead, matching the sibling
// governance checks in ../standards/.
func (d *P2NotFullyUtilizedDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	if data.AzureLicenseTier != "p2" {
		return nil
	}

	if data.AzurePIMAssignments == nil && !data.AzureAccessReviewsProbed {
		return []types.Finding{{
			Type:     d.ID(),
			Severity: types.SeverityInfo,
			Category: string(d.Category()),
			Title:    "Azure AD P2 Features Not Fully Utilized — not determinable (data not probed)",
			Description: "This check was NOT performed: neither PIM role-eligibility data nor the " +
				"access reviews endpoint were probed this audit (missing scope, or the run failed " +
				"before these collection steps — see audit.warnings). This is not a compliance " +
				"verdict either way.",
			Count: 1,
		}}
	}

	var reasons []string
	if data.AzurePIMAssignments != nil && data.AzurePIMAssignments.Eligible.Total == 0 {
		reasons = append(reasons, "no PIM-eligible role assignments (privileged roles are all permanent/direct)")
	}
	if data.AzureAccessReviewsProbed && data.AzureAccessReviewsCount == 0 {
		reasons = append(reasons, "no access reviews configured")
	}
	if len(reasons) == 0 {
		return nil
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "Azure AD P2 Features Not Fully Utilized",
		Description: "P2 is licensed but key P2-gated features are unused: " + strings.Join(reasons, "; ") + ".",
		Count:       1,
	}

	if data.IncludeDetails {
		finding.AffectedEntities = []types.AffectedEntity{
			{
				Type:        "tenant",
				DN:          "tenant",
				Name:        "Azure AD Tenant",
				Description: strings.Join(reasons, "; "),
			},
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewP2NotFullyUtilizedDetector())
}
