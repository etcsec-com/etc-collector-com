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

// Detect flags an enabled user-risk Conditional Access policy that excludes
// the "high" risk level.
//
// Microsoft's own current guidance for the user risk policy is "High", not
// "Medium and above" - that broader threshold is what Microsoft recommends
// for the SEPARATE sign-in risk policy instead. Microsoft Learn, "Risk
// policies - Microsoft Entra ID Protection"
// (learn.microsoft.com/entra/id-protection/howto-identity-protection-configure-risk-policies),
// section "Microsoft recommendations" > "User risk policy": "Organizations
// should select Require risk remediation when user risk level is High."; the
// step-by-step "User risk policy in Conditional Access" section has admins
// select only "High" under "Configure user risk levels needed for policy to
// be enforced". A worked template ("Common Conditional Access policy: User
// risk-based password change") likewise selects "High" alone.
//
// Before this fix, the detector flagged exactly the configuration Microsoft
// itself recommends (High only, no Medium) as a "too low" threshold - the
// opposite of what the source says. The actual, source-grounded gap is a
// user-risk policy that never reaches "high" at all.
func (d *UserRiskLowThresholdDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	finding := types.Finding{
		Type:     d.ID(),
		Severity: types.SeverityMedium,
		Category: string(d.Category()),
		Title:    "User Risk Threshold Too Low",
		Description: "An enabled user risk Conditional Access policy does not cover the 'high' risk level. Microsoft's own " +
			"recommended configuration for the user risk policy is to trigger remediation at High risk.",
		Count: 0,
	}

	var lowThresholdPolicies []types.ConditionalAccessPolicy

	for _, policy := range data.AzureConditionalAccessPolicies {
		if policy.State != "enabled" || len(policy.UserRiskLevels) == 0 {
			continue
		}

		hasHigh := false
		for _, level := range policy.UserRiskLevels {
			if level == "high" {
				hasHigh = true
				break
			}
		}

		// A user-risk policy that never triggers on "high" falls short of
		// Microsoft's own recommended configuration for this policy type.
		if !hasHigh {
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
