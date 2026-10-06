package privileged

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// ExpiredAdminGroupDetector detects expired accounts in admin groups
type ExpiredAdminGroupDetector struct {
	audit.BaseDetector
}

// NewExpiredAdminGroupDetector creates a new detector
func NewExpiredAdminGroupDetector() *ExpiredAdminGroupDetector {
	return &ExpiredAdminGroupDetector{
		BaseDetector: audit.NewBaseDetector("EXPIRED_ACCOUNT_IN_ADMIN_GROUP", audit.CategoryAccounts),
	}
}

// Detect executes the detection
func (d *ExpiredAdminGroupDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.User

	adminGroups := []string{"Domain Admins", "Enterprise Admins", "Schema Admins"}
	now := data.Now

	for _, u := range data.Users {
		if len(u.MemberOf) == 0 {
			continue
		}

		// Check if account is expired
		isExpired := !u.AccountExpires.IsZero() && u.AccountExpires.Before(now)

		if !isExpired {
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
		Title:       "Expired Account in Admin Group",
		Description: "Expired user accounts still present in privileged groups. Should be removed immediately.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewExpiredAdminGroupDetector())
}
