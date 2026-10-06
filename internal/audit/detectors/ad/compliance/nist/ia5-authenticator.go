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
//
// Removed the maximum-password-age sub-check (previously IA-5(1)(d),
// "age > 60 days or 0 is a violation"). Verified against the current,
// published NIST SP 800-63B-4 (final, 2025-07-31, csrc.nist.gov/pubs/sp/800/
// 63/b/4/final), §3.1.1.2 "Password Verifiers": "Verifiers and CSPs SHALL
// NOT require subscribers to change passwords periodically. However,
// verifiers SHALL force a change if there is evidence that the authenticator
// has been compromised." That's a mandatory prohibition (SHALL NOT), not a
// recommendation - a domain that follows modern NIST doctrine and does NOT
// force periodic rotation would have been flagged as NIST-non-compliant by
// the old check, in direct contradiction of the standard it claimed to
// enforce. There is no longer a NIST-endorsed "must rotate within N days"
// number to check against, so the sub-check is removed rather than
// re-thresholded (note: this is a change from the original 2017/2020
// SP 800-63B text, which used the weaker "SHOULD NOT" - if this detector's
// citation predates that shift, that's the source of the contradiction).
// MinPwdLength and PwdHistoryLength are unaffected - nothing found
// contradicts those.
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
		// Windows sets PASSWD_NOTREQD (0x20) on every interdomain trust
		// account by default; its secret is managed by the system, not a
		// human (KB 305144), so it is excluded from both counts below - it
		// is not an authenticator subject to password policy at all.
		if (u.UserAccountControl & types.UACInterdomainTrustAccount) != 0 {
			continue
		}
		if (u.UserAccountControl & uacPasswordNeverExpires) != 0 {
			passwordNeverExpires++
		}
		if (u.UserAccountControl & uacPasswordNotRequired) != 0 {
			passwordNotRequired++
		}
	}

	// This used to also cite "IA-5(1)(d)" for accounts with
	// password-never-expires, and count it toward NIST non-compliance -
	// same doctrine problem as the removed MaxPwdAge check above: SP
	// 800-63B-4 SHALL NOT mandate periodic rotation, so a never-expiring
	// password isn't itself an IA-5(1)(d) violation under current NIST
	// guidance. The count is still surfaced in Details (many
	// privileged/service accounts exempted from any expiration policy is a
	// legitimate credential-hygiene signal worth a manual look), but it no
	// longer drives "non-compliant" or claims a NIST sub-clause it doesn't
	// actually violate.

	if passwordNotRequired > 0 {
		issues = append(issues, fmt.Sprintf("IA-5(1): %d accounts with password not required", passwordNotRequired))
		compliant = false
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "NIST IA-5 Authenticator Management Non-Compliant",
		Description: "Authenticator management does not meet NIST SP 800-53 IA-5 requirements. Interdomain trust accounts (UAC flag 0x800) are not counted as accounts with password not required: Windows sets this flag on them by default, and their secret is managed by the system, not a human (KB 305144).",
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
