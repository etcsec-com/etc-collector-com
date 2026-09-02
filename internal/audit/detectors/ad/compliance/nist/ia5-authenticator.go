package nist

import (
	"context"
	"fmt"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// IA5AuthenticatorDetector checks NIST IA-5 authenticator management compliance
type IA5AuthenticatorDetector struct {
	audit.BaseDetector
}

// NewIA5AuthenticatorDetector creates a new detector
func NewIA5AuthenticatorDetector() *IA5AuthenticatorDetector {
	return &IA5AuthenticatorDetector{
		BaseDetector: audit.NewBaseDetector("NIST_IA_5_AUTHENTICATOR", audit.CategoryCompliance),
	}
}

// UAC flags
const (
	uacPasswordNeverExpires = 0x10000
	uacPasswordNotRequired  = 0x20
)

// Detect executes the detection
func (d *IA5AuthenticatorDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var issues []string
	compliant := true

	// IA-5(1): Password-based authentication
	if data.DomainInfo != nil {
		// IA-5(1)(a): Minimum password length
		if data.DomainInfo.MinPwdLength < 12 {
			issues = append(issues, fmt.Sprintf("IA-5(1)(a): Minimum password length %d < 12", data.DomainInfo.MinPwdLength))
			compliant = false
		}
		// IA-5(1)(d): Password lifetime
		if data.DomainInfo.MaxPwdAge > 60 || data.DomainInfo.MaxPwdAge == 0 {
			issues = append(issues, fmt.Sprintf("IA-5(1)(d): Maximum password age %d not within 60 days", data.DomainInfo.MaxPwdAge))
			compliant = false
		}
		// IA-5(1)(e): Password reuse
		if data.DomainInfo.PwdHistoryLength < 24 {
			issues = append(issues, fmt.Sprintf("IA-5(1)(e): Password history %d < 24", data.DomainInfo.PwdHistoryLength))
			compliant = false
		}
	}

	// Check for accounts with password never expires
	passwordNeverExpires := 0
	passwordNotRequired := 0
	for _, u := range data.Users {
		if !u.Enabled() {
			continue
		}
		if (u.UserAccountControl & uacPasswordNeverExpires) != 0 {
			passwordNeverExpires++
		}
		if (u.UserAccountControl & uacPasswordNotRequired) != 0 {
			passwordNotRequired++
		}
	}

	if passwordNeverExpires > 10 {
		issues = append(issues, fmt.Sprintf("IA-5(1)(d): %d accounts with password never expires", passwordNeverExpires))
		compliant = false
	}

	if passwordNotRequired > 0 {
		issues = append(issues, fmt.Sprintf("IA-5(1): %d accounts with password not required", passwordNotRequired))
		compliant = false
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "NIST IA-5 Authenticator Management Non-Compliant",
		Description: "Authenticator management does not meet NIST SP 800-53 IA-5 requirements.",
		Count:       0,
		Details: map[string]interface{}{
			"framework":            "NIST",
			"control":              "IA-5",
			"publication":          "SP 800-53",
			"passwordNeverExpires": passwordNeverExpires,
			"passwordNotRequired":  passwordNotRequired,
		},
	}

	if !compliant {
		finding.Count = 1
		finding.Details["violations"] = issues
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewIA5AuthenticatorDetector())
}
