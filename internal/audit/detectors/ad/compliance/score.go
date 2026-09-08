package compliance

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// ScoreDetector calculates an overall compliance score
type ScoreDetector struct {
	audit.BaseDetector
}

// NewScoreDetector creates a new detector
func NewScoreDetector() *ScoreDetector {
	return &ScoreDetector{
		BaseDetector: audit.NewBaseDetector("COMPLIANCE_SCORE", audit.CategoryCompliance),
	}
}

// Detect executes the detection
func (d *ScoreDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	score := 100
	deductions := make(map[string]int)

	// Password-length/history thresholds tightened from 12 to 14/24.
	// 12/12 had no source and were looser than BOTH CIS (14 length, 24
	// history) and the DISA STIG (also 14/24) - meaning this score could
	// show 100/100 on the very same domain where CIS_PASSWORD_POLICY and
	// DISA_ACCOUNT_POLICIES (fixed in this same ticket) report High-severity
	// violations. Aligning to the value both standards already agree on
	// removes that specific contradiction; lockout/max-age thresholds are
	// left as this product's own middle-ground judgment call (no single
	// numeric bound is universal across standards there - see the title/
	// description fix below for how that residual gap is now disclosed).
	if data.DomainInfo != nil {
		if data.DomainInfo.MinPwdLength < 14 {
			deductions["weak_password_length"] = 10
			score -= 10
		}
		if data.DomainInfo.PwdHistoryLength < 24 {
			deductions["weak_password_history"] = 5
			score -= 5
		}
		if data.DomainInfo.LockoutThreshold > 10 || data.DomainInfo.LockoutThreshold == 0 {
			deductions["weak_lockout_policy"] = 5
			score -= 5
		}
		if data.DomainInfo.MaxPwdAge > 90 || data.DomainInfo.MaxPwdAge == 0 {
			deductions["weak_password_age"] = 5
			score -= 5
		}
	} else {
		deductions["no_domain_info"] = 15
		score -= 15
	}

	// User account hygiene
	enabledUsers := 0
	disabledUsers := 0
	for _, u := range data.Users {
		if !u.Disabled {
			enabledUsers++
		} else {
			disabledUsers++
		}
	}

	// Check admin count
	adminCount := 0
	for _, u := range data.Users {
		if !u.Disabled && u.AdminCount {
			adminCount++
		}
	}
	if adminCount > 20 {
		deductions["excessive_admins"] = 10
		score -= 10
	}

	// Ensure score doesn't go below 0
	if score < 0 {
		score = 0
	}

	// This "global" score used to be titled/described as an overall
	// assessment while being computed from just 5 password-policy/admin-count
	// signals - a domain could show 100/100 here while CIS_PASSWORD_POLICY,
	// DISA_ACCOUNT_POLICIES or other High-severity compliance detectors in
	// the very same audit fire real violations, since those detectors check
	// entirely different controls this score never looks at (LDAP/SMB
	// signing, audit logging, User Rights Assignment, ANSSI Tier
	// segregation, etc.). A product-level indicator must announce its own
	// actual scope rather than imply completeness it doesn't have (same
	// principle as the ANSSI/CIS/DISA citation fixes elsewhere in this
	// ticket, applied to scope instead of framework attribution).
	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityInfo,
		Category:    string(d.Category()),
		Title:       "Partial Compliance Score (password policy + admin count only)",
		Description: "Product-level score computed from 5 signals only: password length/history/age, lockout policy, and Domain Admins count. It is NOT an overall compliance assessment - a high score here does not mean other compliance detectors (CIS, DISA, ANSSI, NIST, industry) are also passing; they check independent controls this score does not evaluate.",
		Count:       1,
		Details: map[string]interface{}{
			"score":        score,
			"maxScore":     100,
			"scope":        "password policy (length/history/age/lockout) + Domain Admins count only - not an overall compliance measure",
			"deductions":   deductions,
			"totalUsers":   enabledUsers + disabledUsers,
			"enabledUsers": enabledUsers,
			"adminCount":   adminCount,
			"interpretation": map[string]string{
				"95-100": "Excellent - Meets most compliance requirements",
				"85-94":  "Good - Minor improvements recommended",
				"70-84":  "Fair - Several areas need attention",
				"50-69":  "Poor - Significant compliance gaps",
				"0-49":   "Critical - Immediate action required",
			},
		},
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewScoreDetector())
}
