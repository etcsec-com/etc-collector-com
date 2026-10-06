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
		// V-63419/63423/63429/63433/63437 were the wrong STIG
		// entirely - that V-63xxx range is the Windows 10 (client) STIG, not
		// a Windows Server STIG, and even within Windows 10's STIG the
		// numbers were permuted against their actual titles (V-63419 there
		// is "maximum password age <= 60", V-63423 is "minimum password
		// length >= 14", not what each check here claimed). V-63433 and
		// V-63437 don't exist in the Windows 10 STIG at all (confirmed
		// against the mitre/microsoft-windows-10-stig-baseline control
		// list). This is a domain-wide Active Directory account policy, so
		// the applicable STIG is Microsoft Windows Server 2022 (V2R7);
		// replaced with its real, verified V-IDs. The numeric thresholds
		// were already correct and are unchanged, except the lockout
		// threshold's "excluding 0" exemption, which was backwards (see
		// below).
		//
		// mappings.go (out of scope here) currently tags this
		// detector's DISA control as "V-73305", which is itself wrong (that
		// ID is a Windows Server 2016 FTP-server STIG item, unrelated to
		// account policy) - noted as a needed follow-up.

		// WN22-AC-000070 / V-254291: Minimum password length >= 14
		if data.DomainInfo.MinPwdLength < 14 {
			issues = append(issues, fmt.Sprintf("WN22-AC-000070 (V-254291): Minimum password length %d < 14", data.DomainInfo.MinPwdLength))
			compliant = false
		}
		// WN22-AC-000040 / V-254288: Password history >= 24
		if data.DomainInfo.PwdHistoryLength < 24 {
			issues = append(issues, fmt.Sprintf("WN22-AC-000040 (V-254288): Password history %d < 24", data.DomainInfo.PwdHistoryLength))
			compliant = false
		}
		// WN22-AC-000050 / V-254289: Maximum password age <= 60 days, not 0
		if data.DomainInfo.MaxPwdAge > 60 || data.DomainInfo.MaxPwdAge == 0 {
			issues = append(issues, fmt.Sprintf("WN22-AC-000050 (V-254289): Maximum password age %d (must be 1-60 days, not 0)", data.DomainInfo.MaxPwdAge))
			compliant = false
		}
		// WN22-AC-000020 / V-254286: Account lockout threshold <= 3, not 0
		// ("excluding '0', which is unacceptable" - 0 is a violation, not an
		// exemption; the old code had this backwards).
		if data.DomainInfo.LockoutThreshold > 3 || data.DomainInfo.LockoutThreshold == 0 {
			issues = append(issues, fmt.Sprintf("WN22-AC-000020 (V-254286): Account lockout threshold %d (must be 1-3, not 0)", data.DomainInfo.LockoutThreshold))
			compliant = false
		}
		// WN22-AC-000010 / V-254285: Lockout duration >= 15 minutes, or 0
		// (0 = admin unlock required, which is more restrictive and compliant).
		if data.DomainInfo.LockoutDuration > 0 && data.DomainInfo.LockoutDuration < 15 {
			issues = append(issues, fmt.Sprintf("WN22-AC-000010 (V-254285): Lockout duration %d < 15 minutes", data.DomainInfo.LockoutDuration))
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
		Description: "Account policies do not meet the Microsoft Windows Server 2022 STIG (V2R7) account-policy requirements.",
		Count:       0,
	}

	if !compliant {
		finding.Count = 1
		finding.Details = map[string]interface{}{
			"violations": issues,
			"framework":  "DISA",
			"stig":       "Microsoft Windows Server 2022 STIG (V2R7)",
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewAccountPoliciesDetector())
}
