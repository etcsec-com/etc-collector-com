package anssi

import (
	"testing"

	"github.com/etcsec-com/etc-collector/pkg/types"
)

const (
	r12ForcePwdGUID = "00299570-246d-11d0-a768-00aa006e0529" // User-Force-Change-Password extended right

	maskCtrlAcc = 0x00000100
)

// TestANSSIR12_1_RequiresControlAccess pins the R12.1 sibling: an extended
// right is exercised through CONTROL_ACCESS (0x100), so requiring WRITE_PROP
// there would have turned the false positive into a false negative.
func TestANSSIR12_1_RequiresControlAccess(t *testing.T) {
	t.Run("READ_PROP on the extended right does NOT fire", func(t *testing.T) {
		f := r12Detect(t, NewR121ForcePwdResetDetector(), r12Data(types.ACLEntry{
			ObjectDN:   r12TargetDN,
			Trustee:    sidPreWin2000,
			AccessMask: maskReadProp,
			AceType:    "ACCESS_ALLOWED_OBJECT",
			ObjectType: r12ForcePwdGUID,
		}))
		if f.Count != 0 {
			t.Fatalf("READ_PROP must not fire, got count=%d", f.Count)
		}
	})

	t.Run("delegated password reset to a domain group DOES fire", func(t *testing.T) {
		f := r12Detect(t, NewR121ForcePwdResetDetector(), r12Data(types.ACLEntry{
			ObjectDN:   r12TargetDN,
			Trustee:    sidHelpdesk,
			AccessMask: maskCtrlAcc,
			AceType:    "ACCESS_ALLOWED_OBJECT",
			ObjectType: r12ForcePwdGUID,
		}))
		if f.Count != 1 {
			t.Fatalf("CONTROL_ACCESS on User-Force-Change-Password must fire, got count=%d", f.Count)
		}
		if len(f.AffectedEntities) != 1 {
			t.Fatalf("expected 1 actionable entity, got %d", len(f.AffectedEntities))
		}
		if got := f.AffectedEntities[0].Right; got != "User-Force-Change-Password" {
			t.Errorf("right = %q, want User-Force-Change-Password", got)
		}
	})

	t.Run("full control carries the extended right", func(t *testing.T) {
		f := r12Detect(t, NewR121ForcePwdResetDetector(), r12Data(types.ACLEntry{
			ObjectDN:   r12TargetDN,
			Trustee:    sidHelpdesk,
			AccessMask: 0x000F01FF,
			AceType:    "ACCESS_ALLOWED_OBJECT",
			ObjectType: r12ForcePwdGUID,
		}))
		if f.Count != 1 {
			t.Fatalf("full control must fire, got count=%d", f.Count)
		}
	})
}
