package security

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

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

// Detect executes the detection
func (d *ComputerStaleWithAdminGroupsDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	const serverTrustAccount = 0x2000
	var affected []types.Computer

	now := data.Now
	ninetyDaysAgo := now.AddDate(0, 0, -90)

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
		if len(c.MemberOf) > 0 && helpers.IsInAnyGroup(c.MemberOf, helpers.AdminGroups) {
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
