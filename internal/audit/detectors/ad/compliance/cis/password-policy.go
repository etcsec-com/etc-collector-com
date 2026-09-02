package cis

import (
	"context"
	"fmt"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// PasswordPolicyDetector checks CIS password policy compliance
type PasswordPolicyDetector struct {
	audit.BaseDetector
}

// NewPasswordPolicyDetector creates a new detector
func NewPasswordPolicyDetector() *PasswordPolicyDetector {
	return &PasswordPolicyDetector{
		BaseDetector: audit.NewBaseDetector("CIS_PASSWORD_POLICY", audit.CategoryCompliance),
	}
}

// Detect executes the detection
func (d *PasswordPolicyDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var issues []string
	compliant := true

	if data.DomainInfo != nil {
		// CIS 1.1.1: Minimum password length >= 14
		if data.DomainInfo.MinPwdLength < 14 {
			issues = append(issues, fmt.Sprintf("CIS 1.1.1: Minimum password length %d < 14", data.DomainInfo.MinPwdLength))
			compliant = false
		}
		// CIS 1.1.2: Password history >= 24
		if data.DomainInfo.PwdHistoryLength < 24 {
			issues = append(issues, fmt.Sprintf("CIS 1.1.2: Password history %d < 24", data.DomainInfo.PwdHistoryLength))
			compliant = false
		}
		// CIS 1.1.3: Maximum password age <= 60 days
		if data.DomainInfo.MaxPwdAge > 60 {
			issues = append(issues, fmt.Sprintf("CIS 1.1.3: Maximum password age %d > 60 days", data.DomainInfo.MaxPwdAge))
			compliant = false
		}
		// CIS 1.1.4: Minimum password age >= 1 day
		if data.DomainInfo.MinPwdAge < 1 {
			issues = append(issues, fmt.Sprintf("CIS 1.1.4: Minimum password age %d < 1 day", data.DomainInfo.MinPwdAge))
			compliant = false
		}
		// CIS 1.2.1: Account lockout threshold <= 5
		if data.DomainInfo.LockoutThreshold > 5 && data.DomainInfo.LockoutThreshold != 0 {
			issues = append(issues, fmt.Sprintf("CIS 1.2.1: Account lockout threshold %d > 5", data.DomainInfo.LockoutThreshold))
			compliant = false
		}
	} else {
		issues = append(issues, "Domain password policy not available")
		compliant = false
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "CIS Password Policy Non-Compliant",
		Description: "Password policy does not meet CIS Benchmark requirements. CIS requires minimum 14 characters, 24 password history, max age 60 days, min age 1 day, and lockout threshold ≤5.",
		Count:       0,
	}

	if !compliant {
		finding.Count = 1
		finding.Details = map[string]interface{}{
			"violations": issues,
			"framework":  "CIS",
			"benchmark":  "CIS Microsoft Windows Server Benchmark",
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewPasswordPolicyDetector())
}
