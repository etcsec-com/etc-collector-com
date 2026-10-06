package privileged

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/detectors/ad/privgroups"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// printOperatorsSIDSuffixes is the RID suffix for the built-in Print
// Operators group (S-1-5-32-550), matched by SID instead of CN:
// a homonym group grants no real membership, and a renamed real group is
// still caught. Already present in types.PrivilegedSIDSuffixes.
var printOperatorsSIDSuffixes = []string{"-550"}

// PrintOperatorsDetector detects Print Operators membership among enabled
// accounts. Split from the disabled population: a disabled account cannot
// obtain a ticket-granting ticket of its own ([MS-KILE] "Check Account
// Policy for Every TGT Request" - KDC_ERR_CLIENT_REVOKED), so it cannot
// authenticate and cannot exercise the privilege while disabled. See
// PrintOperatorsOnDisabledAccountDetector, which reports that population
// separately, at Low.
type PrintOperatorsDetector struct {
	audit.BaseDetector
}

// NewPrintOperatorsDetector creates a new detector
func NewPrintOperatorsDetector() *PrintOperatorsDetector {
	return &PrintOperatorsDetector{
		BaseDetector: audit.NewBaseDetector("PRINT_OPERATORS_MEMBER", audit.CategoryAccounts),
	}
}

// Detect executes the detection
func (d *PrintOperatorsDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.User

	printOperatorsDNs := privgroups.DNsBySIDSuffix(data, printOperatorsSIDSuffixes)

	for _, u := range data.Users {
		if u.Disabled {
			continue
		}
		if len(u.MemberOf) == 0 {
			continue
		}
		if privgroups.IsMemberOfAny(u.MemberOf, printOperatorsDNs) {
			affected = append(affected, u)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "Print Operators Member",
		Description: "Users in Print Operators group. Can load/unload device drivers, manage printers on domain controllers, sign in locally to domain controllers, and shut them down.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewPrintOperatorsDetector())
}
