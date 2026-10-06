package anssi

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// --- R12.2: User-Account-Restrictions ACL ---
//
// Shares aclEntities and the ADS access-mask constants with
// anssi-r12-1-force-pwd-reset-privs.go (see sub_recos.go).

type R122UserRestrictionsDetector struct{ audit.BaseDetector }

func NewR122UserRestrictionsDetector() *R122UserRestrictionsDetector {
	return &R122UserRestrictionsDetector{BaseDetector: audit.NewBaseDetector("ANSSI_R12_2_USER_RESTRICTIONS_PRIVS", audit.CategoryCompliance)}
}
func (d *R122UserRestrictionsDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// Property-set GUID for User-Account-Restrictions
	const userRestrictionsGUID = "4c164200-20c0-11d0-a768-00aa006e0529"
	var matched []types.ACLEntry
	for _, ace := range data.ACLEntries {
		if !strings.EqualFold(ace.ObjectType, userRestrictionsGUID) {
			continue
		}
		// The check is about the ability to MODIFY userAccountControl. A
		// READ_PROP ACE on the property set conveys no privilege at all.
		if ace.AccessMask&(adsRightDSWriteProp|adsRightGenericWrite|adsRightGenericAll) == 0 {
			continue
		}
		if isWellKnownAdminTrustee(ace.Trustee) {
			continue
		}
		matched = append(matched, ace)
	}
	return wrapFinding(d, "ANSSI R12.2 - User-Account-Restrictions accordé hors comptes système",
		"ANSSI R12.2 (sub-reco) - the User-Account-Restrictions property set lets the holder modify userAccountControl bits (disable, no-preauth, smartcard required, etc.). Should be restricted to Tier 0 admins only.",
		types.SeverityHigh, len(matched), aclEntities(data, matched))
}

func init() {
	audit.MustRegister(NewR122UserRestrictionsDetector())
}
