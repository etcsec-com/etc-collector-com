package privileged

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// SensitiveDelegationDetector detects sensitive accounts with unconstrained delegation
type SensitiveDelegationDetector struct {
	audit.BaseDetector
}

// NewSensitiveDelegationDetector creates a new detector
func NewSensitiveDelegationDetector() *SensitiveDelegationDetector {
	return &SensitiveDelegationDetector{
		BaseDetector: audit.NewBaseDetector("SENSITIVE_DELEGATION", audit.CategoryAccounts),
	}
}

// Detect executes the detection
func (d *SensitiveDelegationDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.User

	privilegedGroups := []string{"Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators"}

	for _, u := range data.Users {
		if len(u.MemberOf) == 0 {
			continue
		}

		hasUnconstrainedDeleg := (u.UserAccountControl & types.UACTrustedForDelegation) != 0

		if !hasUnconstrainedDeleg {
			continue
		}

		// Check if privileged
		isPrivileged := false
		for _, dn := range u.MemberOf {
			for _, group := range privilegedGroups {
				if strings.Contains(dn, "CN="+group) {
					isPrivileged = true
					break
				}
			}
			if isPrivileged {
				break
			}
		}

		if isPrivileged {
			affected = append(affected, u)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityCritical,
		Category:    string(d.Category()),
		Title:       "Sensitive Account with Delegation",
		Description: "Privileged accounts (Domain/Enterprise Admins) with unconstrained delegation. Extreme security risk.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewSensitiveDelegationDetector())
}
