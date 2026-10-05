package anssi

import (
	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// Shared helpers for the R12.1/R12.2 sub-recommendation detectors
// (anssi-r12-1-force-pwd-reset-privs.go, anssi-r12-2-user-restrictions-privs.go).
// The other former occupants of this file (R2.2, R15.1, R15.2, R29.1, R34.2,
// R36.1) now each live in their own detector file, one detector per file.

// Access-mask bits that turn an ACE on a property set or an extended right
// into an actual privilege grant. Reading a property is not a
// privilege: R12.2 used to match on the property-set GUID alone, which made
// every `BUILTIN\Pre-Windows 2000 Compatible Access` READ_PROP ACE - the one
// AD places on every user object at domain install - a HIGH finding.
const (
	adsRightDSWriteProp     = 0x00000020 // ADS_RIGHT_DS_WRITE_PROP
	adsRightDSControlAccess = 0x00000100 // ADS_RIGHT_DS_CONTROL_ACCESS (exercises an extended right)
	adsRightGenericWrite    = 0x40000000
	adsRightGenericAll      = 0x10000000
)

// aclEntities projects matching ACEs onto aclEntry entities so every ANSSI ACL
// finding is actionable (trustee + right + target). Callers pass only the ACEs
// they counted, so Count == len(entities).
func aclEntities(data *audit.DetectorData, matched []types.ACLEntry) []types.AffectedEntity {
	if !data.IncludeDetails {
		return nil
	}
	out := make([]types.AffectedEntity, 0, len(matched))
	for _, ace := range matched {
		if ent := audit.ACLEntryToAffectedEntity(ace, data.ObjectByDN, data.ObjectBySID); ent.Type != "" {
			out = append(out, ent)
			continue
		}
		out = append(out, data.EntityForDN(ace.ObjectDN))
	}
	return out
}
