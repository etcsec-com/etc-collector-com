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
		// Sub-item numbers below were permuted against the current
		// CIS Microsoft Windows Server Benchmark (verified against v3.0/v4.0
		// Server 2022 Benchmark and Tenable's audit-item listings). The
		// numeric thresholds for length/history/min-age were already
		// correct; only the labels were swapped and max-age's threshold
		// itself was wrong (60 belongs to the DISA STIG variant, not the
		// standard CIS Benchmark).

		// CIS 1.1.4: Minimum password length >= 14
		if data.DomainInfo.MinPwdLength < 14 {
			issues = append(issues, fmt.Sprintf("CIS 1.1.4: Minimum password length %d < 14", data.DomainInfo.MinPwdLength))
			compliant = false
		}
		// CIS 1.1.1: Enforce password history >= 24
		if data.DomainInfo.PwdHistoryLength < 24 {
			issues = append(issues, fmt.Sprintf("CIS 1.1.1: Password history %d < 24", data.DomainInfo.PwdHistoryLength))
			compliant = false
		}
		// CIS 1.1.2: Maximum password age <= 365 days, but not 0 (0 = never
		// expires, which is non-compliant, not exempt).
		if data.DomainInfo.MaxPwdAge > 365 || data.DomainInfo.MaxPwdAge == 0 {
			issues = append(issues, fmt.Sprintf("CIS 1.1.2: Maximum password age %d (must be 1-365 days, not 0/never)", data.DomainInfo.MaxPwdAge))
			compliant = false
		}
		// CIS 1.1.3: Minimum password age >= 1 day
		if data.DomainInfo.MinPwdAge < 1 {
			issues = append(issues, fmt.Sprintf("CIS 1.1.3: Minimum password age %d < 1 day", data.DomainInfo.MinPwdAge))
			compliant = false
		}
		// CIS 1.2.2: Account lockout threshold <= 5, but not 0 (0 = never
		// locks out, which is non-compliant, not exempt - CIS: "excluding
		// '0', which is unacceptable").
		if data.DomainInfo.LockoutThreshold > 5 || data.DomainInfo.LockoutThreshold == 0 {
			issues = append(issues, fmt.Sprintf("CIS 1.2.2: Account lockout threshold %d (must be 1-5, not 0)", data.DomainInfo.LockoutThreshold))
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
		Description: "Password policy does not meet CIS Benchmark requirements. CIS requires minimum 14 characters, 24 password history, max age 1-365 days (not 0), min age 1 day, and lockout threshold 1-5 (not 0).",
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
