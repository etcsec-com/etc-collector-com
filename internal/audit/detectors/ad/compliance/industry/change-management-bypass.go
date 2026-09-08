package industry

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// ChangeManagementBypassDetector checks for change management compliance issues
type ChangeManagementBypassDetector struct {
	audit.BaseDetector
}

// NewChangeManagementBypassDetector creates a new detector
func NewChangeManagementBypassDetector() *ChangeManagementBypassDetector {
	return &ChangeManagementBypassDetector{
		BaseDetector: audit.NewBaseDetector("CHANGE_MANAGEMENT_BYPASS", audit.CategoryCompliance),
	}
}

// Source-check outcome. The >10/>5 thresholds below have no official
// source (searched: no CIS/DISA/ANSSI/NIST control specifies a numeric
// "too many admins" bound for change-management bypass risk) - they are
// this product's own heuristic, and the framework tag already reflects that
// ("Industry Best Practices", not a numbered standard); no false attribution
// exists to retire. Two real limitations remain, documented rather than
// silently left as-is (both require new data-plumbing this file's
// scope doesn't cover - no nested-group-membership resolution helper
// exists for AD in this codebase, unlike the Azure side):
//   - direct memberOf substring match only: a user who reaches Domain/
//     Enterprise Admins via NESTED group membership (member of a group
//     that's a member of Domain Admins) is invisible to this count.
//   - matching is by the well-known English group name; an org that has
//     renamed Domain Admins/Enterprise Admins (AD allows renaming built-in
//     groups; the RID stays fixed but the name doesn't) evades detection.

// Detect executes the detection
func (d *ChangeManagementBypassDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var issues []string

	// Check for excessive privileged accounts that could bypass change management
	adminCount := 0
	for _, u := range data.Users {
		if !u.Enabled() {
			continue
		}
		for _, memberOf := range u.MemberOf {
			if strings.Contains(strings.ToLower(memberOf), "domain admins") ||
				strings.Contains(strings.ToLower(memberOf), "enterprise admins") {
				adminCount++
				break
			}
		}
	}

	if adminCount > 10 {
		issues = append(issues, "Excessive privileged accounts increase change management bypass risk")
	}

	// Check for service accounts with admin privileges
	serviceAdmins := 0
	for _, u := range data.Users {
		if len(u.ServicePrincipalNames) > 0 && u.AdminCount {
			serviceAdmins++
		}
	}

	if serviceAdmins > 5 {
		issues = append(issues, "Multiple service accounts with admin privileges")
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "Change Management Compliance Review",
		Description: "Review privileged access to ensure change management processes cannot be easily bypassed.",
		Count:       0,
		Details: map[string]interface{}{
			"category":             "Industry Best Practices",
			"privilegedAccounts":   adminCount,
			"serviceAccountsAdmin": serviceAdmins,
		},
	}

	if len(issues) > 0 {
		finding.Count = 1
		finding.Details["issues"] = issues
		finding.Details["recommendations"] = []string{
			"Implement just-in-time privileged access",
			"Require approval workflows for privileged operations",
			"Enable enhanced auditing for all admin activities",
			"Separate service account privileges from interactive admin accounts",
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewChangeManagementBypassDetector())
}
