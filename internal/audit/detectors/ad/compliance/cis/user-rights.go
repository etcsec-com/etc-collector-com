package cis

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// UserRightsDetector checks CIS user rights compliance
type UserRightsDetector struct {
	audit.BaseDetector
}

// NewUserRightsDetector creates a new detector
func NewUserRightsDetector() *UserRightsDetector {
	return &UserRightsDetector{
		BaseDetector: audit.NewBaseDetector("CIS_USER_RIGHTS", audit.CategoryCompliance),
	}
}

// Detect executes the detection
func (d *UserRightsDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var issues []string

	// Check for excessive admin accounts (CIS 2.2.x series)
	adminCount := 0
	enterpriseAdminCount := 0
	schemaAdminCount := 0

	for _, u := range data.Users {
		if !u.Enabled() {
			continue
		}
		for _, memberOf := range u.MemberOf {
			memberOfLower := strings.ToLower(memberOf)
			if strings.Contains(memberOfLower, "domain admins") {
				adminCount++
			}
			if strings.Contains(memberOfLower, "enterprise admins") {
				enterpriseAdminCount++
			}
			if strings.Contains(memberOfLower, "schema admins") {
				schemaAdminCount++
			}
		}
	}

	// CIS recommends minimal privileged group membership
	if adminCount > 5 {
		issues = append(issues, "CIS 2.2.x: Excessive Domain Admins membership")
	}
	if enterpriseAdminCount > 2 {
		issues = append(issues, "CIS 2.2.x: Excessive Enterprise Admins membership")
	}
	if schemaAdminCount > 1 {
		issues = append(issues, "CIS 2.2.x: Excessive Schema Admins membership")
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "CIS User Rights Assignment Review",
		Description: "User rights assignments should follow CIS Benchmark recommendations for least privilege.",
		Count:       0,
		Details: map[string]interface{}{
			"framework":        "CIS",
			"benchmark":        "CIS Microsoft Windows Server Benchmark",
			"domainAdmins":     adminCount,
			"enterpriseAdmins": enterpriseAdminCount,
			"schemaAdmins":     schemaAdminCount,
		},
	}

	if len(issues) > 0 {
		finding.Count = 1
		finding.Details["violations"] = issues
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewUserRightsDetector())
}
