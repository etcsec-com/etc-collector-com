package privileged

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/detectors/ad/privgroups"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// accountOperatorsSIDSuffixes is the RID suffix for the built-in Account
// Operators group (S-1-5-32-548), matched by SID instead of CN:
// a homonym group grants no real membership, and a renamed real group is
// still caught. Already present in types.PrivilegedSIDSuffixes.
var accountOperatorsSIDSuffixes = []string{"-548"}

// AccountOperatorsDetector detects Account Operators membership among
// enabled accounts. Split from the disabled population: a disabled account
// cannot obtain a ticket-granting ticket of its own ([MS-KILE] "Check
// Account Policy for Every TGT Request" - KDC_ERR_CLIENT_REVOKED), so it
// cannot authenticate and cannot exercise the privilege while disabled. See
// AccountOperatorsOnDisabledAccountDetector, which reports that population
// separately, at Low.
type AccountOperatorsDetector struct {
	audit.BaseDetector
}

// NewAccountOperatorsDetector creates a new detector
func NewAccountOperatorsDetector() *AccountOperatorsDetector {
	return &AccountOperatorsDetector{
		BaseDetector: audit.NewBaseDetector("ACCOUNT_OPERATORS_MEMBER", audit.CategoryAccounts),
	}
}

// Detect executes the detection
func (d *AccountOperatorsDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.User

	accountOperatorsDNs := privgroups.DNsBySIDSuffix(data, accountOperatorsSIDSuffixes)

	for _, u := range data.Users {
		if u.Disabled {
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
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "Account Operators Member",
		Description: "Users in Account Operators group. Can create/modify user accounts.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewAccountOperatorsDetector())
}
