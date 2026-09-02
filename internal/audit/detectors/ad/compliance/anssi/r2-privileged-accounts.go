package anssi

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// R2PrivilegedAccountsDetector checks ANSSI R2 privileged accounts compliance
type R2PrivilegedAccountsDetector struct {
	audit.BaseDetector
}

// NewR2PrivilegedAccountsDetector creates a new detector
func NewR2PrivilegedAccountsDetector() *R2PrivilegedAccountsDetector {
	return &R2PrivilegedAccountsDetector{
		BaseDetector: audit.NewBaseDetector("ANSSI_R2_PRIVILEGED_ACCOUNTS", audit.CategoryCompliance),
	}
}

// Detect executes the detection
func (d *R2PrivilegedAccountsDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var issues []string

	// Count domain admins
	daCount := 0
	for _, u := range data.Users {
		if !u.Enabled() {
			continue
		}
		for _, memberOf := range u.MemberOf {
			if strings.Contains(strings.ToLower(memberOf), "domain admins") {
				daCount++
				break
			}
		}
	}

	// ANSSI recommends minimal DA accounts (< 10)
	if daCount > 10 {
		issues = append(issues, "More than 10 Domain Admin accounts")
	}

	// Check for service accounts in DA
	for _, u := range data.Users {
		if len(u.ServicePrincipalNames) > 0 {
			for _, memberOf := range u.MemberOf {
				if strings.Contains(strings.ToLower(memberOf), "domain admins") {
					issues = append(issues, "Service account in Domain Admins group")
					break
				}
			}
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "ANSSI R2 - Privileged Accounts Non-Compliant",
		Description: "Privileged account management does not meet ANSSI R2 recommendations. Minimize DA accounts and separate service accounts.",
		Count:       0,
	}

	if len(issues) > 0 {
		finding.Count = 1
		finding.Details = map[string]interface{}{
			"violations":   issues,
			"framework":    "ANSSI",
			"control":      "R2",
			"domainAdmins": daCount,
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewR2PrivilegedAccountsDetector())
}
