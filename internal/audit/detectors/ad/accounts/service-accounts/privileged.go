package serviceaccounts

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// PrivilegedDetector detects service accounts in privileged groups
type PrivilegedDetector struct {
	audit.BaseDetector
}

// NewPrivilegedDetector creates a new detector
func NewPrivilegedDetector() *PrivilegedDetector {
	return &PrivilegedDetector{
		BaseDetector: audit.NewBaseDetector("SERVICE_ACCOUNT_PRIVILEGED", audit.CategoryAccounts),
	}
}

var privilegedGroups = []string{
	"Domain Admins",
	"Enterprise Admins",
	"Schema Admins",
	"Administrators",
	"Backup Operators",
	"Account Operators",
	"Server Operators",
}

// Detect executes the detection
func (d *PrivilegedDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.User

	for _, u := range data.Users {
		// Must be a service account
		if !isServiceAccount(u) {
			continue
		}
		// Must be enabled
		if u.Disabled {
			continue
		}
		// Check if in privileged groups
		if len(u.MemberOf) == 0 {
			continue
		}

		for _, dn := range u.MemberOf {
			inPrivilegedGroup := false
			for _, group := range privilegedGroups {
				if strings.Contains(dn, "CN="+group) {
					inPrivilegedGroup = true
					break
				}
			}
			if inPrivilegedGroup {
				affected = append(affected, u)
				break
			}
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityCritical,
		Category:    string(d.Category()),
		Title:       "Service Account in Privileged Group",
		Description: "Service accounts with membership in privileged groups (Domain Admins, etc.). If compromised, attackers gain full domain control.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
		finding.Details = map[string]interface{}{
			"recommendation": "Remove service accounts from privileged groups. Grant only the minimum permissions needed for the service to function.",
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewPrivilegedDetector())
}
