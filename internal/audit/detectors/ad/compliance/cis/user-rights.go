package cis

import (
	"context"

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

// This detector's name and citations promise CIS 2.2.x "User Rights
// Assignment" (the GPO section listing SIDs granted each privilege, e.g.
// "Act as part of the operating system", "Enable computer and user accounts
// to be trusted for delegation"), but the code counted memberOf entries in
// Domain/Enterprise/Schema Admins against unsourced thresholds (5/2/1) -
// group membership, not User Rights Assignment, and the collected
// PrivilegeRights data (populated from GptTmpl.inf's [Privilege Rights]
// section for exactly this purpose, see internal/audit/gpo_policy.go) was
// never read. Replaced with two real, sourced User Rights Assignment
// checks using PrivilegeRights fields that were already being collected:
//   - CIS 2.2.4 "Act as part of the operating system" -> "No One"
//   - CIS 2.2.29 (numbered 2.2.21-2.2.37 depending on benchmark version)
//     "Enable computer and user accounts to be trusted for delegation" -> "No One"
// Both confirmed against the current CIS Microsoft Windows Server Benchmark
// (Tenable audit-item listings, Server 2019/2022/2025 editions).

// Detect executes the detection
func (d *UserRightsDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var issues []string
	var sidsWithTCB, sidsWithDelegation []string

	for _, p := range data.GPOPolicies {
		if p == nil || p.PrivilegeRights == nil {
			continue
		}
		sidsWithTCB = append(sidsWithTCB, p.PrivilegeRights.SeTcbPrivilege...)
		sidsWithDelegation = append(sidsWithDelegation, p.PrivilegeRights.SeEnableDelegationPrivilege...)
	}

	if len(sidsWithTCB) > 0 {
		issues = append(issues, "CIS 2.2.4: 'Act as part of the operating system' is not set to 'No One'")
	}
	if len(sidsWithDelegation) > 0 {
		issues = append(issues, "CIS 2.2.29: 'Enable computer and user accounts to be trusted for delegation' is not set to 'No One'")
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "CIS User Rights Assignment Review",
		Description: "User rights assignments should follow CIS Benchmark recommendations: 'Act as part of the operating system' and 'Enable computer and user accounts to be trusted for delegation' should both be set to 'No One'.",
		Count:       0,
		Details: map[string]interface{}{
			"framework":                "CIS",
			"benchmark":                "CIS Microsoft Windows Server Benchmark",
			"actAsPartOfOSGrantedTo":   sidsWithTCB,
			"delegationTrustGrantedTo": sidsWithDelegation,
		},
	}

	if len(issues) > 0 {
		finding.Count = len(issues)
		finding.Details["violations"] = issues
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewUserRightsDetector())
}
