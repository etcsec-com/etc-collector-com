package disa

import (
	"context"
	"fmt"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// AccountPoliciesDetector checks DISA STIG account policy compliance
type AccountPoliciesDetector struct {
	audit.BaseDetector
}

// NewAccountPoliciesDetector creates a new detector
func NewAccountPoliciesDetector() *AccountPoliciesDetector {
	return &AccountPoliciesDetector{
		BaseDetector: audit.NewBaseDetector("DISA_ACCOUNT_POLICIES", audit.CategoryCompliance),
	}
}

// Detect executes the detection
func (d *AccountPoliciesDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var issues []string
	compliant := true

	if data.DomainInfo != nil {
		// V-63419: Minimum password length >= 14
		if data.DomainInfo.MinPwdLength < 14 {
			issues = append(issues, fmt.Sprintf("V-63419: Minimum password length %d < 14", data.DomainInfo.MinPwdLength))
			compliant = false
		}
		// V-63423: Password history >= 24
		if data.DomainInfo.PwdHistoryLength < 24 {
			issues = append(issues, fmt.Sprintf("V-63423: Password history %d < 24", data.DomainInfo.PwdHistoryLength))
			compliant = false
		}
		// V-63429: Maximum password age <= 60 days
		if data.DomainInfo.MaxPwdAge > 60 {
			issues = append(issues, fmt.Sprintf("V-63429: Maximum password age %d > 60 days", data.DomainInfo.MaxPwdAge))
			compliant = false
		}
		// V-63433: Account lockout threshold <= 3
		if data.DomainInfo.LockoutThreshold > 3 && data.DomainInfo.LockoutThreshold != 0 {
			issues = append(issues, fmt.Sprintf("V-63433: Account lockout threshold %d > 3", data.DomainInfo.LockoutThreshold))
			compliant = false
		}
		// V-63437: Lockout duration >= 15 minutes or until admin unlocks
		if data.DomainInfo.LockoutDuration > 0 && data.DomainInfo.LockoutDuration < 15 {
			issues = append(issues, fmt.Sprintf("V-63437: Lockout duration %d < 15 minutes", data.DomainInfo.LockoutDuration))
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
		Title:       "DISA STIG Account Policies Non-Compliant",
		Description: "Account policies do not meet DISA STIG requirements for Windows Server.",
		Count:       0,
	}

	if !compliant {
		finding.Count = 1
		finding.Details = map[string]interface{}{
			"violations": issues,
			"framework":  "DISA",
			"stig":       "Windows Server STIG",
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewAccountPoliciesDetector())
}
