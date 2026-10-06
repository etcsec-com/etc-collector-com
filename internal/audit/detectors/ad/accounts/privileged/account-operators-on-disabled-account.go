package privileged

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/detectors/ad/privgroups"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// AccountOperatorsOnDisabledAccountDetector checks for disabled direct
// members of Account Operators (S-1-5-32-548). Split out of
// AccountOperatorsDetector: a disabled account cannot obtain a
// ticket-granting ticket of its own ([MS-KILE] "Check Account Policy for
// Every TGT Request" - KDC_ERR_CLIENT_REVOKED), so it cannot authenticate
// and the privilege is dormant while the account stays disabled. Membership
// itself is not removed by this state - it persists and returns to full
// effect the instant the account is re-enabled, which is the residual risk
// this detector keeps reporting. Same convention as the delegation family
// (*_ON_DISABLED_ACCOUNT): the suffix names the population covered, not the
// state of a mechanism - _DISABLED alone is reserved elsewhere in this
// catalog for "a protection was turned off".
type AccountOperatorsOnDisabledAccountDetector struct {
	audit.BaseDetector
}

// NewAccountOperatorsOnDisabledAccountDetector creates a new detector
func NewAccountOperatorsOnDisabledAccountDetector() *AccountOperatorsOnDisabledAccountDetector {
	return &AccountOperatorsOnDisabledAccountDetector{
		BaseDetector: audit.NewBaseDetector("ACCOUNT_OPERATORS_MEMBER_ON_DISABLED_ACCOUNT", audit.CategoryAccounts),
	}
}

// Detect executes the detection
func (d *AccountOperatorsOnDisabledAccountDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.User

	accountOperatorsDNs := privgroups.DNsBySIDSuffix(data, accountOperatorsSIDSuffixes)

	for _, u := range data.Users {
		if !u.Disabled {
			continue
		}
		if len(u.MemberOf) == 0 {
			continue
		}
		if privgroups.IsMemberOfAny(u.MemberOf, accountOperatorsDNs) {
			affected = append(affected, u)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityLow,
		Category:    string(d.Category()),
		Title:       "Account Operators Member (Disabled Account)",
		Description: "Disabled users who are direct members of Account Operators cannot authenticate while disabled, so they cannot exercise the privilege. Membership is not removed by this state - it returns to full effect the instant the account is re-enabled. Remediation: remove the account from the group.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewAccountOperatorsOnDisabledAccountDetector())
}
