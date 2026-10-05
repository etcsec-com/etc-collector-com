package adcs

import (
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
)

// TestESC7NotRegistered documents the RETIRER decision (re-revue):
// a previous fix had already silenced ESC7_CA_VULNERABLE_ACL (Detect always returns
// Count:0, explained in a comment) because it read the AD object's DACL
// instead of the CA's own registry security descriptor
// (ManageCA/ManageCertificates) - the actual ESC7 surface, which no
// provider in this repo collects (no MS-RRP/ICertAdmin2 client in go.mod).
// A follow-up exhaustive audit re-examined it and went one step further:
// a detector that can structurally never measure its subject should not
// stay in the registry/catalog looking like it does - fully deregistered
// here, on the same "un detecteur qui devine est pire qu'un controle
// absent" doctrine, now applied to "a detector that can never emit at all"
// too. Re-enable once a registry/RPC provider for the CA's own security
// descriptor exists (tracked separately, protocol choice pending Founder).
func TestESC7NotRegistered(t *testing.T) {
	if _, ok := audit.DefaultRegistry.Get("ESC7_CA_VULNERABLE_ACL"); ok {
		t.Fatal("ESC7_CA_VULNERABLE_ACL must not be registered: no provider reads the CA's own " +
			"registry security descriptor (ManageCA/ManageCertificates), the actual ESC7 surface")
	}
}
