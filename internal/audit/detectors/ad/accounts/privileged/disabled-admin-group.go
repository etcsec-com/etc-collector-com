package privileged

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// DisabledAdminGroupDetector detects disabled accounts in admin groups
type DisabledAdminGroupDetector struct {
	audit.BaseDetector
}

// NewDisabledAdminGroupDetector creates a new detector
func NewDisabledAdminGroupDetector() *DisabledAdminGroupDetector {
	return &DisabledAdminGroupDetector{
		BaseDetector: audit.NewBaseDetector("DISABLED_ACCOUNT_IN_ADMIN_GROUP", audit.CategoryAccounts),
	}
}

// Detect executes the detection
func (d *DisabledAdminGroupDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.User

	adminGroups := []string{"Domain Admins", "Enterprise Admins", "Schema Admins"}

	for _, u := range data.Users {
		if len(u.MemberOf) == 0 {
			continue
		}

		// Check if disabled (UAC flag 0x2 or Disabled field)
		isDisabled := u.Disabled || (u.UserAccountControl&0x2) != 0

		if !isDisabled {
			continue
		}

		// Check if in admin group
		for _, dn := range u.MemberOf {
			inAdminGroup := false
			for _, group := range adminGroups {
				if strings.Contains(dn, "CN="+group) {
					inAdminGroup = true
					break
				}
			}
			if inAdminGroup {
				affected = append(affected, u)
				break
			}
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "Disabled Account in Admin Group",
		Description: "Disabled user accounts still present in privileged groups. Should be removed immediately.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewDisabledAdminGroupDetector())
}
