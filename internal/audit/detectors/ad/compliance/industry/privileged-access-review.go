package industry

import (
	"context"
	"strconv"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// PrivilegedAccessReviewDetector checks for privileged access review compliance
type PrivilegedAccessReviewDetector struct {
	audit.BaseDetector
}

// NewPrivilegedAccessReviewDetector creates a new detector
func NewPrivilegedAccessReviewDetector() *PrivilegedAccessReviewDetector {
	return &PrivilegedAccessReviewDetector{
		BaseDetector: audit.NewBaseDetector("PRIVILEGED_ACCESS_REVIEW_MISSING", audit.CategoryCompliance),
	}
}

// Detect executes the detection
func (d *PrivilegedAccessReviewDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var staleAdmins []string
	now := data.Now
	staleThreshold := now.AddDate(0, 0, -90) // 90 days

	// Check for stale privileged accounts
	for _, u := range data.Users {
		if !u.Enabled() {
			continue
		}

		isAdmin := false
		for _, memberOf := range u.MemberOf {
			memberOfLower := strings.ToLower(memberOf)
			if strings.Contains(memberOfLower, "domain admins") ||
				strings.Contains(memberOfLower, "enterprise admins") ||
				strings.Contains(memberOfLower, "schema admins") ||
				strings.Contains(memberOfLower, "administrators") {
				isAdmin = true
				break
			}
		}

		if isAdmin && !u.LastLogon.IsZero() && u.LastLogon.Before(staleThreshold) {
			staleAdmins = append(staleAdmins, u.SAMAccountName)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "Privileged Access Review Required",
		Description: "Regular review of privileged access is required for compliance. Some privileged accounts show signs of inactivity.",
		Count:       0,
		Details: map[string]interface{}{
			"category":    "Industry Best Practices",
			"staleAdmins": len(staleAdmins),
			"threshold":   "90 days without login",
		},
	}

	if len(staleAdmins) > 0 {
		finding.Count = len(staleAdmins)
		if len(staleAdmins) <= 10 {
			finding.Details["staleAdminAccounts"] = staleAdmins
		} else {
			finding.Details["staleAdminAccounts"] = staleAdmins[:10]
			finding.Details["note"] = "Showing first 10 of " + strconv.Itoa(len(staleAdmins)) + " stale admin accounts"
		}
		finding.Details["recommendations"] = []string{
			"Review privileged access quarterly",
			"Remove or disable inactive admin accounts",
			"Implement privileged access management (PAM)",
			"Use just-in-time privileged access where possible",
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewPrivilegedAccessReviewDetector())
}
