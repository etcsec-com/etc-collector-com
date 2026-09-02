package domainpolicy

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// WeakPasswordPolicyDetector detects weak password policy settings
type WeakPasswordPolicyDetector struct {
	audit.BaseDetector
}

// NewWeakPasswordPolicyDetector creates a new detector
func NewWeakPasswordPolicyDetector() *WeakPasswordPolicyDetector {
	return &WeakPasswordPolicyDetector{
		BaseDetector: audit.NewBaseDetector("WEAK_PASSWORD_POLICY", audit.CategoryAdvanced),
	}
}

// Detect executes the detection
func (d *WeakPasswordPolicyDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	if data.DomainInfo == nil {
		return []types.Finding{{
			Type:        d.ID(),
			Severity:    types.SeverityMedium,
			Category:    string(d.Category()),
			Title:       "Weak Password Policy",
			Description: "Unable to check domain password policy.",
			Count:       0,
		}}
	}

	minPwdLength := data.DomainInfo.MinPwdLength
	maxPwdAge := data.DomainInfo.MaxPwdAge
	pwdHistoryLength := data.DomainInfo.PwdHistoryLength

	// Weak if: min length < 14, max age > 90 days, or history < 24
	isWeak := minPwdLength < 14 || maxPwdAge > 90 || pwdHistoryLength < 24

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "Weak Password Policy",
		Description: "Domain password policy below minimum standards. Enables easier password cracking.",
		Count:       0,
	}

	if isWeak {
		finding.Count = 1
		if data.IncludeDetails {
			finding.AffectedEntities = []types.AffectedEntity{types.DomainInfoToAffectedEntity(data.DomainInfo)}
			finding.Details = map[string]interface{}{
				"minPwdLength":     minPwdLength,
				"maxPwdAge":        maxPwdAge,
				"pwdHistoryLength": pwdHistoryLength,
			}
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewWeakPasswordPolicyDetector())
}
