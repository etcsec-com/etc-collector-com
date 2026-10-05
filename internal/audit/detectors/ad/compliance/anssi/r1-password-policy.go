package anssi

import (
	"context"
	"fmt"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// R1PasswordPolicyDetector checks the domain-wide password policy against
// etc-collector product benchmarks.
//
// "ANSSI R1" never covered this: PA-099's R1 (p.28) is "Adopter un modèle
// de gestion des accès à privilèges" (adopt a tiered privileged access
// model) - unrelated to password-policy thresholds (same conclusion
// r2-privileged-accounts.go already reached independently for its own
// "<10 Domain Admins" check). The real source for password-policy numbers
// is ANSSI-PG-078 ("Recommandations relatives à l'authentification
// multifacteur et aux mots de passe", 08/10/2021), referenced by PA-099 as
// document [2]. Checked against the full text of PG-078:
//
//   - Length: Table 3 (p.27) gives a context-dependent range - 9-11 chars
//     ("faible à moyen"), 12-14 ("moyen à fort"), ≥15 ("fort à très fort").
//     No single mandated number for a domain-wide default policy.
//   - History: R-adjacent text (p.30) recommends rejecting reuse "parmi les
//     X derniers mots de passe" but leaves X unspecified.
//   - Lockout: R10 (p.21) requires SOME mechanism limiting authentication
//     attempts over time ("il est recommandé de mettre en œuvre un
//     mécanisme limitant le nombre de tentatives d'authentification"), but
//     gives no specific attempt count.
//   - Max age: R24 (p.29) recommends NOT imposing a default expiry on
//     non-sensitive accounts when the password policy is otherwise strong;
//     R25 (p.30) recommends expiry ONLY for privileged accounts, with a
//     suggested window of 1 to 3 years (365-1095 days) - not ≤90 days.
//
// So length/history/lockout-count are etc-collector product benchmarks
// (same treatment as daCountBenchmark in r2-privileged-accounts.go), not
// ANSSI-mandated numbers, and must not be presented as one. The previous
// maxAge<=90-day rule was actively CONTRARY to PG-078 R24/R25 (which
// recommend a 1-3 year window for privileged accounts and no forced expiry
// at all for everyone else) and has been removed rather than relabeled.
type R1PasswordPolicyDetector struct {
	audit.BaseDetector
}

// NewR1PasswordPolicyDetector creates a new detector
func NewR1PasswordPolicyDetector() *R1PasswordPolicyDetector {
	return &R1PasswordPolicyDetector{
		BaseDetector: audit.NewBaseDetector("ANSSI_R1_PASSWORD_POLICY", audit.CategoryCompliance),
	}
}

// Product benchmarks - not ANSSI-mandated numbers (see type doc above).
const (
	minLengthBenchmark        = 12 // PG-078 Table 3 (p.27) "moyen à fort" bracket (12-14)
	pwdHistoryBenchmark       = 12 // PG-078 (p.30) requires SOME reuse restriction; count unspecified
	lockoutThresholdBenchmark = 10 // PG-078 R10 (p.21) requires SOME rate-limiting; count unspecified
)

// Detect executes the detection
func (d *R1PasswordPolicyDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var issues []string
	compliant := true

	if data.DomainInfo != nil {
		if data.DomainInfo.MinPwdLength < minLengthBenchmark {
			issues = append(issues, fmt.Sprintf("Minimum password length %d < %d (product benchmark)", data.DomainInfo.MinPwdLength, minLengthBenchmark))
			compliant = false
		}
		if data.DomainInfo.PwdHistoryLength < pwdHistoryBenchmark {
			issues = append(issues, fmt.Sprintf("Password history %d < %d (product benchmark)", data.DomainInfo.PwdHistoryLength, pwdHistoryBenchmark))
			compliant = false
		}
		if data.DomainInfo.LockoutThreshold == 0 {
			// PG-078 R10 (p.21) requires SOME mechanism limiting
			// authentication attempts. Threshold 0 means Windows never
			// locks the account out - no rate limiting at all. The
			// previous implementation explicitly excluded 0 from this
			// check (`LockoutThreshold != 0`), treating "no lockout ever"
			// as compliant - the opposite of what R10 requires.
			issues = append(issues, "No account lockout mechanism configured (threshold=0) - PG-078 R10 requires some mechanism limiting authentication attempts")
			compliant = false
		} else if data.DomainInfo.LockoutThreshold > lockoutThresholdBenchmark {
			issues = append(issues, fmt.Sprintf("Lockout threshold %d > %d (product benchmark)", data.DomainInfo.LockoutThreshold, lockoutThresholdBenchmark))
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
		Title:       "Password Policy Non-Compliant (product benchmark)",
		Description: fmt.Sprintf("Domain password policy does not meet etc-collector's product benchmark: minimum %d characters, password history of %d, and an account-lockout mechanism enabled (threshold between 1 and %d). These are product benchmarks, not ANSSI-mandated numbers - PG-078 (ANSSI's password guide) leaves the exact length/history/attempt-count to context (see PG-078 R10, R21, Table 3) while requiring that SOME lockout mechanism exist. No maximum password age is checked here: PG-078 R24/R25 recommend against a short forced expiry for non-privileged accounts and suggest 1-3 years for privileged ones, which a blanket domain-wide rule cannot express (Tier 0-specific password policy coverage is checked separately by ANSSI_R40_NO_PSO_TIER0).", minLengthBenchmark, pwdHistoryBenchmark, lockoutThresholdBenchmark),
		Count:       0,
	}

	if !compliant {
		finding.Count = 1
		finding.Details = map[string]interface{}{
			"violations": issues,
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewR1PasswordPolicyDetector())
}
