package other

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// safeDelegationPrivilegeSIDs mirrors the safe set used by the sibling
// SeBackupPrivilege/SeDebugPrivilege GPO detectors (privilege-rights-abuse.go):
// only built-in Administrators and SYSTEM are expected to hold this right.
var safeDelegationPrivilegeSIDs = map[string]bool{
	"S-1-5-32-544": true, // BUILTIN\Administrators
	"S-1-5-18":     true, // LOCAL SYSTEM
}

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

// Detect executes the detection.
//
// SeEnableDelegationPrivilege is a GPO [Privilege Rights]
// user right, not a per-user LDAP attribute. It is parsed from GptTmpl.inf
// into PrivilegeRights.SeEnableDelegationPrivilege (internal/providers/smb/
// gptmpl_parser.go) and exposed via data.GPOPolicies - never onto
// types.User. The former User.HasSeEnableDelegationPrivilege field this
// detector read was never assigned anywhere and was always false.
func (d *DelegationPrivilegeDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "Delegation Privilege",
		Description: "Account has SeEnableDelegationPrivilege. Can enable delegation on user/computer accounts.",
		Count:       0,
	}

	sids := helpers.FindPrivilegeRight(data.GPOPolicies, func(pr *audit.PrivilegeRights) []string {
		return pr.SeEnableDelegationPrivilege
	})

	var unsafe []string
	for _, sid := range sids {
		if !safeDelegationPrivilegeSIDs[sid] {
			unsafe = append(unsafe, sid)
		}
	}

	finding.Count = len(unsafe)
	if len(unsafe) > 0 {
		finding.Details = map[string]interface{}{
			"unsafeSIDs":     unsafe,
			"recommendation": "Limit SeEnableDelegationPrivilege to Administrators only.",
		}
		if data.IncludeDetails {
			entities := make([]types.AffectedEntity, len(unsafe))
			for i, sid := range unsafe {
				entities[i] = audit.SIDToEntityWithCache(sid, data)
			}
			finding.AffectedEntities = entities
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewDelegationPrivilegeDetector())
}
