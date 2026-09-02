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

	// Password policy checks
	if data.DomainInfo != nil {
		if data.DomainInfo.MinPwdLength < 12 {
			deductions["weak_password_length"] = 10
			score -= 10
		}
		if data.DomainInfo.PwdHistoryLength < 12 {
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

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityInfo,
		Category:    string(d.Category()),
		Title:       "Compliance Score Assessment",
		Description: "Overall compliance score based on detected policy settings and configurations.",
		Count:       1,
		Details: map[string]interface{}{
			"score":        score,
			"maxScore":     100,
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
