package nist

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// AC2AccountManagementDetector checks NIST AC-2 account management compliance
type AC2AccountManagementDetector struct {
	audit.BaseDetector
}

// NewAC2AccountManagementDetector creates a new detector
func NewAC2AccountManagementDetector() *AC2AccountManagementDetector {
	return &AC2AccountManagementDetector{
		BaseDetector: audit.NewBaseDetector("NIST_AC_2_ACCOUNT_MANAGEMENT", audit.CategoryCompliance),
	}
}

// Detect executes the detection
func (d *AC2AccountManagementDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var issues []string
	now := data.Now
	staleThreshold := now.AddDate(0, 0, -90)

	// AC-2(3): Disable inactive accounts
	inactiveAccounts := 0
	for _, u := range data.Users {
		if u.Enabled() && !u.LastLogon.IsZero() && u.LastLogon.Before(staleThreshold) {
			inactiveAccounts++
		}
	}

	if inactiveAccounts > 0 {
		issues = append(issues, "AC-2(3): Inactive accounts not disabled")
	}

	// AC-2(4): Automated audit actions - check for excessive admins
	adminCount := 0
	for _, u := range data.Users {
		if u.Enabled() && u.AdminCount {
			adminCount++
		}
	}

	if adminCount > 20 {
		issues = append(issues, "AC-2(4): Excessive privileged accounts detected")
	}

	// AC-2(7): Privileged accounts - check for service accounts with admin rights
	serviceAdmins := 0
	for _, u := range data.Users {
		if len(u.ServicePrincipalNames) > 0 {
			for _, memberOf := range u.MemberOf {
				if strings.Contains(strings.ToLower(memberOf), "domain admins") {
					serviceAdmins++
					break
				}
			}
		}
	}

	if serviceAdmins > 0 {
		issues = append(issues, "AC-2(7): Service accounts in privileged groups")
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "NIST AC-2 Account Management Non-Compliant",
		Description: "Account management practices do not fully meet NIST SP 800-53 AC-2 requirements.",
		Count:       0,
		Details: map[string]interface{}{
			"framework":        "NIST",
			"control":          "AC-2",
			"publication":      "SP 800-53",
			"inactiveAccounts": inactiveAccounts,
			"adminAccounts":    adminCount,
			"serviceAdmins":    serviceAdmins,
		},
	}

	if len(issues) > 0 {
		finding.Count = 1
		finding.Details["violations"] = issues
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewAC2AccountManagementDetector())
}
