package other

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// DelegationPrivilegeDetector detects accounts with SeEnableDelegationPrivilege
type DelegationPrivilegeDetector struct {
	audit.BaseDetector
}

// NewDelegationPrivilegeDetector creates a new detector
func NewDelegationPrivilegeDetector() *DelegationPrivilegeDetector {
	return &DelegationPrivilegeDetector{
		BaseDetector: audit.NewBaseDetector("DELEGATION_PRIVILEGE", audit.CategoryAdvanced),
	}
}

// Detect executes the detection
func (d *DelegationPrivilegeDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.User

	for _, u := range data.Users {
		// Check if user has SeEnableDelegationPrivilege
		if u.HasSeEnableDelegationPrivilege {
			affected = append(affected, u)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "Delegation Privilege",
		Description: "Account has SeEnableDelegationPrivilege. Can enable delegation on user/computer accounts.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewDelegationPrivilegeDetector())
}
