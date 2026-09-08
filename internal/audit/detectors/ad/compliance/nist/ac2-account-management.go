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
//
// Two fixes, verified against NIST SP 800-53 Rev 5 (nvlpubs.nist.gov/
// nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf, Chapter 3, pp. 19-22).
//  1. Framing: AC-2(3) ("Disable accounts within [Assignment:
//     organization-defined time period]...have been inactive for
//     [Assignment: organization-defined time period]"), AC-2(4) (automated
//     audit actions, no threshold at all), and AC-2(7) (privileged-account
//     administration, no count limit) mandate NO specific numbers - every
//     threshold is organization-defined. The 90-day/20-admin thresholds
//     below satisfy the control by picking SOME defined value (which is all
//     NIST asks for), but the Description previously implied these exact
//     numbers were themselves NIST requirements. Reworded to say so. This
//     also only covers a narrow slice of AC-2's many sub-requirements
//     (account types, approval workflow, periodic review process, notification
//     timing, etc. are not observable from this data and are not checked).
//  2. lastLogon is a per-DC, non-replicated attribute - auditing against
//     whichever DC this collector happened to query undercounts activity on
//     OTHER domain controllers, producing false "inactive" positives in any
//     multi-DC domain (confirmed on the lab domain, which has 2). Now
//     compares against whichever of lastLogon / lastLogonTimestamp
//     (replicated, ~14-day lag) is more recent - same fix already applied
//     to industry.PrivilegedAccessReviewDetector for the identical bug.
func (d *AC2AccountManagementDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var issues []string
	now := data.Now
	staleThreshold := now.AddDate(0, 0, -90)

	// AC-2(3): Disable inactive accounts
	inactiveAccounts := 0
	for _, u := range data.Users {
		if !u.Enabled() {
			continue
		}
		lastActivity := u.LastLogon
		if u.LastLogonTimestamp.After(lastActivity) {
			lastActivity = u.LastLogonTimestamp
		}
		if !lastActivity.IsZero() && lastActivity.Before(staleThreshold) {
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
		Description: "Account management practices do not meet ETC's organization-defined thresholds implementing a narrow slice of NIST SP 800-53 AC-2 (inactive-account disable, privileged-account count, service accounts in privileged groups). AC-2 itself leaves these thresholds organization-defined - the specific numbers below are ETC-chosen defaults, not values mandated by the standard - and this check does not cover AC-2's full scope (account-type authorization, approval workflow, periodic access review process, and notification timing are not observable from this data).",
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
