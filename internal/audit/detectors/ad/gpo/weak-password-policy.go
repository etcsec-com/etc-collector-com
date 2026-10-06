package gpo

import (
	"context"
	"fmt"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// WeakPasswordPolicyDetector checks for weak password policy in GPO.
//
// Source check: the threshold was hard-coded at 12, while both this
// detector's own Description text and the current CIS Microsoft Windows
// Server Benchmark / Microsoft security baseline recommend 14 characters
// minimum (CIS control "Ensure 'Minimum password length' is set to '14 or
// more characters'"). A domain set at exactly 12 - under the current
// recommendation - was therefore reported as compliant. Fixed to 14. This
// detector reads DomainInfo.MinPwdLength, a single domain-wide value; it
// does not differentiate standard vs. privileged accounts (Fine-Grained
// Password Policies would be needed for that), so the Description no
// longer implies it does.
type WeakPasswordPolicyDetector struct {
	audit.BaseDetector
}

// NewWeakPasswordPolicyDetector creates a new detector
func NewWeakPasswordPolicyDetector() *WeakPasswordPolicyDetector {
	return &WeakPasswordPolicyDetector{
		BaseDetector: audit.NewBaseDetector("GPO_WEAK_PASSWORD_POLICY", audit.CategoryGPO),
	}
}

// Detect executes the detection
func (d *WeakPasswordPolicyDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	minLength := 0
	if data.DomainInfo != nil {
		minLength = data.DomainInfo.MinPwdLength
	}

	const recommendedMinLength = 14
	isWeak := minLength < recommendedMinLength

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "Weak Password Policy",
		Description: fmt.Sprintf("Domain password policy requires only %d characters minimum. The CIS Microsoft Windows Server Benchmark recommends at least %d characters minimum password length.", minLength, recommendedMinLength),
		Count:       0,
	}

	if isWeak {
		finding.Count = 1
		if data.IncludeDetails {
			// Find the Default Domain Policy GPO for the DN
			gpoEntity := types.AffectedEntity{Type: "gpo", Name: "Default Domain Policy"}
			for i := range data.GPOs {
				if data.GPOs[i].DisplayName == "Default Domain Policy" {
					gpoEntity = types.GPOToAffectedEntity(&data.GPOs[i])
					break
				}
			}
			finding.AffectedEntities = []types.AffectedEntity{gpoEntity}
		}
		finding.Details = map[string]interface{}{
			"currentMinLength":     minLength,
			"recommendedMinLength": recommendedMinLength,
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewWeakPasswordPolicyDetector())
}
