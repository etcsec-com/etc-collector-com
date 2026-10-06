package anssi

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// --- R12.1: User-Force-Change-Password ACL on privileged accounts ---
//
// Shares aclEntities and the ADS access-mask constants with
// anssi-r12-2-user-restrictions-privs.go (see sub_recos.go).

type R121ForcePwdResetDetector struct{ audit.BaseDetector }

func NewR121ForcePwdResetDetector() *R121ForcePwdResetDetector {
	return &R121ForcePwdResetDetector{BaseDetector: audit.NewBaseDetector("ANSSI_R12_1_FORCE_PWD_RESET_PRIVS", audit.CategoryCompliance)}
}
func (d *R121ForcePwdResetDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// Extended-right GUID for User-Force-Change-Password
	const forceChangePwdGUID = "00299570-246d-11d0-a768-00aa006e0529"
	var matched []types.ACLEntry
	for _, ace := range data.ACLEntries {
		if !strings.EqualFold(ace.ObjectType, forceChangePwdGUID) {
			continue
		}
		// An extended right is exercised through CONTROL_ACCESS, not
		// WRITE_PROP - full control (0xF01FF) carries it too. Requiring a
		// write bit here would be a false negative on the very delegation
		// this check exists to find.
		if ace.AccessMask&(adsRightDSControlAccess|adsRightGenericAll) == 0 {
			continue
		}
		if isWellKnownAdminTrustee(ace.Trustee) {
			continue
		}
		matched = append(matched, ace)
	}
	return wrapFinding(d, "ANSSI R12.1 - User-Force-Change-Password accordé hors comptes système",
		"ANSSI R12.1 (sub-reco) - the extended right User-Force-Change-Password lets the holder reset arbitrary user passwords without knowing the old one. Should be restricted to Tier 0 admin groups only.",
		types.SeverityHigh, len(matched), aclEntities(data, matched))
}

func init() {
	audit.MustRegister(NewR121ForcePwdResetDetector())
}
