package anssi

import (
	"context"
	"fmt"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// R1PasswordPolicyDetector checks ANSSI R1 password policy compliance
type R1PasswordPolicyDetector struct {
	audit.BaseDetector
}

// NewR1PasswordPolicyDetector creates a new detector
func NewR1PasswordPolicyDetector() *R1PasswordPolicyDetector {
	return &R1PasswordPolicyDetector{
		BaseDetector: audit.NewBaseDetector("ANSSI_R1_PASSWORD_POLICY", audit.CategoryCompliance),
	}
}

// Detect executes the detection
func (d *R1PasswordPolicyDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var issues []string
	compliant := true

	if data.DomainInfo != nil {
		if data.DomainInfo.MinPwdLength < 12 {
			issues = append(issues, fmt.Sprintf("Minimum password length %d < 12 required", data.DomainInfo.MinPwdLength))
			compliant = false
		}
		if data.DomainInfo.PwdHistoryLength < 12 {
			issues = append(issues, fmt.Sprintf("Password history %d < 12 required", data.DomainInfo.PwdHistoryLength))
			compliant = false
		}
		if data.DomainInfo.LockoutThreshold > 5 && data.DomainInfo.LockoutThreshold != 0 {
			issues = append(issues, fmt.Sprintf("Lockout threshold %d > 5 allowed", data.DomainInfo.LockoutThreshold))
			compliant = false
		}
		if data.DomainInfo.MaxPwdAge > 90 {
			issues = append(issues, fmt.Sprintf("Max password age %d > 90 days", data.DomainInfo.MaxPwdAge))
			compliant = false
		}
	} else {
		issues = append(issues, "Password policy not configured or not readable")
		compliant = false
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "ANSSI R1 - Password Policy Non-Compliant",
		Description: "Password policy does not meet ANSSI R1 recommendations. ANSSI requires minimum 12 characters, password history of 12, lockout threshold ≤5, and max age ≤90 days.",
		Count:       0,
	}

	if !compliant {
		finding.Count = 1
		finding.Details = map[string]interface{}{
			"violations": issues,
			"framework":  "ANSSI",
			"control":    "R1",
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewR1PasswordPolicyDetector())
}
