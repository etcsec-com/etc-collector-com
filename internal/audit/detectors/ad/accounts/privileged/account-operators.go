package privileged

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// AccountOperatorsDetector detects Account Operators membership
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

	for _, u := range data.Users {
		if len(u.MemberOf) == 0 {
			continue
		}
		for _, dn := range u.MemberOf {
			if strings.Contains(dn, "CN=Account Operators") {
				affected = append(affected, u)
				break
			}
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
