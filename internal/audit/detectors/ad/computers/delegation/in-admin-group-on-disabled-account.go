package delegation

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/detectors/ad/privgroups"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// InAdminGroupOnDisabledAccountDetector checks for disabled computer
// accounts that are direct members of a privileged group. Split out of
// InAdminGroupDetector, on the same model as the computer delegation pair
// in this same package (UnconstrainedDelegationDetector /
// UnconstrainedDelegationOnDisabledAccountDetector): a disabled computer
// account cannot authenticate ([MS-KILE] "Check Account Policy for Every
// TGT Request" - KDC_ERR_CLIENT_REVOKED), so it cannot exercise the
// privilege while disabled. Membership itself is not removed by this state
// - it persists and reasserts full exploitability the instant the account
// is re-enabled, which is the residual risk this detector keeps reporting.
// Same convention as UNCONSTRAINED_DELEGATION_ON_DISABLED_ACCOUNT and
// SERVER_OPERATORS_MEMBER_ON_DISABLED_ACCOUNT: the suffix names the
// population covered, not the state of a mechanism - _DISABLED alone is
// reserved elsewhere in this catalog for "a protection was turned off".
type InAdminGroupOnDisabledAccountDetector struct {
	audit.BaseDetector
}

// NewInAdminGroupOnDisabledAccountDetector creates a new detector
func NewInAdminGroupOnDisabledAccountDetector() *InAdminGroupOnDisabledAccountDetector {
	return &InAdminGroupOnDisabledAccountDetector{
		BaseDetector: audit.NewBaseDetector("COMPUTER_IN_ADMIN_GROUP_ON_DISABLED_ACCOUNT", audit.CategoryComputers),
	}
}

// Detect executes the detection. Uses the same inAdminGroupSIDSuffixes set
// and privgroups resolution as InAdminGroupDetector, in this same file's
// sibling in-admin-group.go.
func (d *InAdminGroupOnDisabledAccountDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.Computer

	adminDNs := privgroups.DNsBySIDSuffix(data, inAdminGroupSIDSuffixes)

	for _, c := range data.Computers {
		if !c.Disabled {
			continue
		}
		if len(c.MemberOf) > 0 && privgroups.IsMemberOfAny(c.MemberOf, adminDNs) {
			affected = append(affected, c)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityLow,
		Category:    string(d.Category()),
		Title:       "Computer in Admin Group (Disabled Account)",
		Description: "Disabled computer account is a direct member of a privileged group protected by AdminSDHolder (Domain Admins, Enterprise Admins, Administrators, Schema Admins, Account/Backup/Print/Server Operators, Key/Enterprise Key Admins, Domain Controllers), matched by SID. It cannot authenticate while disabled, so it cannot exercise the privilege. Membership is not removed by this state - it returns to full effect the instant the account is re-enabled. Remediation: remove the account from the group.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedComputerEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewInAdminGroupOnDisabledAccountDetector())
}
