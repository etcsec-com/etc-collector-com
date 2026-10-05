package anssi

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// --- R31: Trust TGT delegation forbidden cross-forest ---
//
// See r28_to_r33_trusts.go for the isIncoming helper shared across this
// group.

type R31TrustTGTDelegationDetector struct{ audit.BaseDetector }

func NewR31TrustTGTDelegationDetector() *R31TrustTGTDelegationDetector {
	return &R31TrustTGTDelegationDetector{BaseDetector: audit.NewBaseDetector("ANSSI_R31_TRUST_TGT_DELEGATION", audit.CategoryCompliance)}
}
func (d *R31TrustTGTDelegationDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// ANSSI PA-099 (full-text source audit) R26 (p.43), "Interdire la
	// délégation Kerberos à travers les relations d'approbation entrantes":
	// applies to INCOMING trusts (not "across forest boundaries" broadly),
	// and the mechanism it names is the netdom /EnableTGTDelegation:No
	// switch. (The real R31 in PA-099 is unrelated: reusable secrets in
	// SYSVOL scripts/GPP, p.49.) The bit values 0x200/0x800 and the
	// "TRUST_ATTRIBUTE_DISABLE_AUTH_TARGET_VALIDATION" name previously cited
	// here do not appear anywhere in PA-099 and are unverifiable against it.
	//
	// KNOWN LIMITATION: EnableTGTDelegation is not currently collected by
	// the LDAP trust parser, so R26 compliance cannot be directly measured.
	// This detector is now at least scoped to the right trust direction
	// (incoming), using SelectiveAuth as a heuristic proxy - it is NOT
	// equivalent to EnableTGTDelegation and should be treated as "not
	// verified", not as a confirmed R26 reading.
	count := 0
	for _, t := range data.Trusts {
		if !isIncoming(t) {
			continue
		}
		if !t.SelectiveAuth {
			count++
		}
	}
	return wrapFinding(d, "ANSSI PA-099 R26 - Trust entrant potentiellement permissif à la délégation Kerberos (non vérifié)",
		"ANSSI PA-099 R26 (p.43) requires incoming trusts to have Kerberos delegation disabled (EnableTGTDelegation:No). KNOWN LIMITATION: EnableTGTDelegation is not currently collected - this finding uses Selective Authentication as an imperfect proxy on incoming trusts and does not directly verify R26 compliance; treat as \"not verified\", not as a confirmed violation.",
		types.SeverityHigh, count, nil)
}

func init() {
	audit.MustRegister(NewR31TrustTGTDelegationDetector())
}
