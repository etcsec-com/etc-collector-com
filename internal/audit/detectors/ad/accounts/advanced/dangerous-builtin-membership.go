package advanced

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// DangerousBuiltinMembershipDetector detects accounts in dangerous built-in groups
type DangerousBuiltinMembershipDetector struct {
	audit.BaseDetector
}

// NewDangerousBuiltinMembershipDetector creates a new detector
func NewDangerousBuiltinMembershipDetector() *DangerousBuiltinMembershipDetector {
	return &DangerousBuiltinMembershipDetector{
		BaseDetector: audit.NewBaseDetector("DANGEROUS_BUILTIN_MEMBERSHIP", audit.CategoryAccounts),
	}
}

var dangerousGroups = []string{
	"Cert Publishers",
	"RAS and IAS Servers",
	"Windows Authorization Access Group",
	"Terminal Server License Servers",
	"Incoming Forest Trust Builders",
	"Performance Log Users",
	"Performance Monitor Users",
	"Distributed COM Users",
	"Remote Desktop Users",
	"Network Configuration Operators",
	"Cryptographic Operators",
	"Event Log Readers",
	"Hyper-V Administrators",
	"Access Control Assistance Operators",
	"Remote Management Users",
}

// Detect executes the detection
func (d *DangerousBuiltinMembershipDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.User

	for _, u := range data.Users {
		if u.Disabled || len(u.MemberOf) == 0 {
			continue
		}

		if helpers.IsInAnyGroup(u.MemberOf, dangerousGroups) {
			affected = append(affected, u)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "Dangerous Built-in Group Membership",
		Description: "User accounts with membership in overlooked but dangerous built-in groups. These groups grant elevated privileges that may allow privilege escalation.",
		Count:       len(affected),
	}

	if data.IncludeDetails {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
		finding.Details = map[string]interface{}{
			"dangerousGroups": dangerousGroups,
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewDangerousBuiltinMembershipDetector())
}
