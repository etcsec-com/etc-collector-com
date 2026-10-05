package anssi

import (
	"strings"

	"github.com/etcsec-com/etc-collector/pkg/types"
)

// R28-R33 cover the trust hygiene block. Each detector now lives in its own
// file (anssi-r28-krbtgt-not-rotated.go, anssi-r29-trust-sid-filtering-
// off.go, anssi-r30-trust-selective-auth-off.go, anssi-r31-trust-tgt-
// delegation.go, anssi-r32-trust-rc4-allowed.go, anssi-r33-external-trust-
// permissive.go). What remains here is genuinely shared across them.

func isExternalOrForest(t types.Trust) bool {
	tt := strings.ToLower(t.TrustType)
	return tt == "external" || tt == "forest"
}

// isOutgoing reports whether t has an outgoing leg - i.e. Outbound or
// Bidirectional. PA-099's trust-hardening recommendations (R24, R25+) are
// explicitly scoped to "relations d'approbation sortantes" (outgoing
// trusts); a purely Inbound trust is out of their stated scope.
func isOutgoing(t types.Trust) bool {
	switch strings.ToLower(t.TrustDirection) {
	case "outbound", "bidirectional":
		return true
	default:
		return false
	}
}

// isIncoming reports whether t has an incoming leg - i.e. Inbound or
// Bidirectional. PA-099 R26 ("Interdire la délégation Kerberos à travers
// les relations d'approbation entrantes") is scoped to incoming trusts.
func isIncoming(t types.Trust) bool {
	switch strings.ToLower(t.TrustDirection) {
	case "inbound", "bidirectional":
		return true
	default:
		return false
	}
}
