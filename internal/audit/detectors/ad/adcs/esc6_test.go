package adcs

import (
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
)

// TestESC6EditfFlagIsNotRegistered documents the RETIRER decision:
// ESC6_EDITF_FLAG emitted an unconditional Count:0 - no provider (ldap/
// azure/network/smb) reads the EDITF_ATTRIBUTESUBJECTALTNAME2 flag, which
// lives in the CA server's own registry, not in LDAP/Graph. A detector
// that can structurally never fire produces a permanent false "OK" on a
// genuinely vulnerable CA - worse than no control. Retired (deregistered)
// until the product collects EditFlags (a new RPC/registry CA provider).
func TestESC6EditfFlagIsNotRegistered(t *testing.T) {
	if _, ok := audit.DefaultRegistry.Get("ESC6_EDITF_FLAG"); ok {
		t.Fatal("ESC6_EDITF_FLAG est enregistre alors qu'aucune donnee collectee " +
			"ne permet de mesurer EDITF_ATTRIBUTESUBJECTALTNAME2 : ce detecteur " +
			"doit rester desenregistre jusqu'a l'ajout d'un provider capable de le lire")
	}
}
