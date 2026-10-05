package anssi

import (
	"context"
	"fmt"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// R28-R33 cover the trust hygiene block. Despite the filename, a full-text
// audit of ANSSI PA-099 found most of these IDs do NOT correspond to
// PA-099 recommendations R28-R33 - see each detector's own comment for the
// correct citation where one exists:
//   R28 - krbtgt password rotation cadence (PA-099 R41, p.54-55)
//   R29 - Trust SID filtering on outgoing extra-forest trusts (PA-099 R24, p.41)
//   R30 - Selective Authentication on outgoing extra-forest trusts (PA-099 R25+, p.42)
//   R31 - Kerberos delegation forbidden across incoming trusts (PA-099 R26, p.43; not directly measurable - see below)
//   R32 - Trust must use AES (no RC4 cross-realm) - unchanged, not audited here
//   R33 - Permissive external trust (PA-099 R24 primary + R25+ compensating fallback; R24's own text, not a single "R33")
//
// See r28_to_r33_trusts.go for the isOutgoing/isIncoming/isExternalOrForest
// helpers shared across this group.

// --- R28: krbtgt password rotation ---

type R28KrbtgtRotationDetector struct{ audit.BaseDetector }

func NewR28KrbtgtRotationDetector() *R28KrbtgtRotationDetector {
	return &R28KrbtgtRotationDetector{BaseDetector: audit.NewBaseDetector("ANSSI_R28_KRBTGT_NOT_ROTATED", audit.CategoryCompliance)}
}
func (d *R28KrbtgtRotationDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// krbtgt is the user whose objectSID ends with -502.
	//
	// ANSSI PA-099 R41 (p.53): "Le mot de passe du compte krbtgt doit être
	// renouvelé chaque année par les administrateurs" - once a year, not
	// every 180 days. The previous 180-day threshold was stricter than the
	// source and flagged Severity Critical on a state (180-365 days since
	// last rotation) ANSSI itself considers compliant.
	threshold := data.Now.AddDate(-1, 0, 0)
	var krbtgt *types.User
	for i := range data.Users {
		u := &data.Users[i]
		if strings.HasSuffix(u.ObjectSID, "-502") || strings.EqualFold(u.SAMAccountName, "krbtgt") {
			krbtgt = u
			break
		}
	}
	count := 0
	if krbtgt != nil && !krbtgt.PasswordLastSet.IsZero() && krbtgt.PasswordLastSet.Before(threshold) {
		count = 1
	}
	desc := "ANSSI PA-099 R41 requires rotating the krbtgt account password at least once a year (\"renouvelé chaque année\", p.53)."
	if krbtgt != nil && !krbtgt.PasswordLastSet.IsZero() {
		days := int(data.Now.Sub(krbtgt.PasswordLastSet).Hours() / 24)
		desc = fmt.Sprintf("%s Last krbtgt password change: %d days ago.", desc, days)
	}
	// krbtgt is a single, always-known object; the finding previously
	// carried no AffectedEntities at all (motif(c): count fires, nothing
	// actionable for the client).
	var entities []types.AffectedEntity
	if count == 1 && data.IncludeDetails {
		entities = []types.AffectedEntity{types.UserToAffectedEntity(krbtgt)}
	}
	return wrapFinding(d, "ANSSI PA-099 R41 - krbtgt non roté (>1 an)", desc, types.SeverityCritical, count, entities)
}

func init() {
	audit.MustRegister(NewR28KrbtgtRotationDetector())
}
