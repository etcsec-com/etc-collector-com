package security

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/detectors/ad/privgroups"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// staleAdminGroupSIDSuffixes is helpers.AdminGroups (Domain Admins,
// Enterprise Admins, Schema Admins, Administrators, Account Operators,
// Server Operators, Backup Operators, Print Operators) translated to RID
// suffixes: matched by SID, not CN, so a homonym group doesn't
// false-positive and a renamed real group is still caught. All 8 suffixes
// already appear in types.PrivilegedSIDSuffixes.
var staleAdminGroupSIDSuffixes = []string{"-512", "-519", "-518", "-544", "-548", "-549", "-551", "-550"}

// ComputerStaleWithAdminGroupsDetector detects stale computers in admin groups
type ComputerStaleWithAdminGroupsDetector struct {
	audit.BaseDetector
}

// NewComputerStaleWithAdminGroupsDetector creates a new detector
func NewComputerStaleWithAdminGroupsDetector() *ComputerStaleWithAdminGroupsDetector {
	return &ComputerStaleWithAdminGroupsDetector{
		BaseDetector: audit.NewBaseDetector("COMPUTER_STALE_WITH_ADMIN_GROUPS", audit.CategoryComputers),
	}
}

// Detect executes the detection.
//
// Source: Microsoft Learn, "Accounts security posture assessment - Microsoft
// Defender for Identity", sections "Remove stale Active Directory accounts"
// and "Remove Stale Service Accounts" (learn.microsoft.com/en-us/defender-for-identity/
// security-posture-assessments/accounts): both use the same 90-day
// no-logon threshold to define "stale" that this detector already uses -
// the value is confirmed, not invented.
//
// Known limitation, not fixed here: privgroups.IsMemberOfAny resolves
// direct memberOf only, not nested group membership - a computer in an
// admin group only via an intermediate group is not caught.
func (d *ComputerStaleWithAdminGroupsDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	const serverTrustAccount = 0x2000
	var affected []types.Computer

	now := data.Now
	ninetyDaysAgo := now.AddDate(0, 0, -90)
	adminDNs := privgroups.DNsBySIDSuffix(data, staleAdminGroupSIDSuffixes)

	for _, c := range data.Computers {
		if c.Disabled || (c.UserAccountControl&serverTrustAccount) != 0 {
			continue
		}

		// Check if stale
		lastLogon := c.LastLogonTimestamp
		if lastLogon.IsZero() {
			lastLogon = c.LastLogon
		}

		if lastLogon.IsZero() || !lastLogon.Before(ninetyDaysAgo) {
			continue
		}

		// Check if in admin groups (unusual!)
		if len(c.MemberOf) > 0 && privgroups.IsMemberOfAny(c.MemberOf, adminDNs) {
			affected = append(affected, c)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "Stale Computers in Admin Groups",
		Description: "Computer accounts inactive 90+ days but in privileged groups. Highly unusual configuration.",
		Count:       len(affected),
		Details: map[string]interface{}{
			"recommendation": "Remove computers from admin groups and investigate",
			"note":           "Computers should NOT be in admin groups",
		},
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedComputerEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewComputerStaleWithAdminGroupsDetector())
}
