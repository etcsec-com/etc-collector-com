package anssi

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// T_023 — ANSSI_R12_2 emitted 1130 HIGH findings on DC01 with zero
// affectedEntities, every one of them the READ_PROP ACE that AD itself places
// on each user object at domain install (qa verdict §3). R12.1 carries the same
// code defect. These tests pin both the false positive and the true positive.

const (
	r12DomainDN     = "DC=example,DC=com"
	r12TargetDN     = "CN=Akira Jackson,OU=IT," + r12DomainDN
	r12RestrictGUID = "4c164200-20c0-11d0-a768-00aa006e0529" // User-Account-Restrictions property set
	r12ForcePwdGUID = "00299570-246d-11d0-a768-00aa006e0529" // User-Force-Change-Password extended right

	sidPreWin2000   = "S-1-5-32-554" // BUILTIN\Pre-Windows 2000 Compatible Access
	sidDomainAdmins = "S-1-5-21-1234567890-1111111111-2222222222-512"
	sidHelpdesk     = "S-1-5-21-1234567890-1111111111-2222222222-1337"

	maskReadProp  = 0x00000010
	maskWriteProp = 0x00000020
	maskCtrlAcc   = 0x00000100
)

func r12Data(aces ...types.ACLEntry) *audit.DetectorData {
	return &audit.DetectorData{
		IncludeDetails: true,
		ACLEntries:     aces,
		ObjectByDN: map[string]*audit.ObjectMeta{
			r12TargetDN: {DN: r12TargetDN, Name: "Akira Jackson", EntityType: types.EntityTypeUser},
		},
	}
}

func r12Detect(t *testing.T, d audit.Detector, data *audit.DetectorData) types.Finding {
	t.Helper()
	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("%s: expected exactly 1 finding, got %d", d.ID(), len(findings))
	}
	return findings[0]
}

// TestANSSIR12_2_IgnoresReadOnlyACE covers acceptance §2.
func TestANSSIR12_2_IgnoresReadOnlyACE(t *testing.T) {
	t.Run("AD's default READ_PROP ACE does NOT fire", func(t *testing.T) {
		// The exact DC01 shape: mask 0x10 held by S-1-5-32-554, ×1130.
		f := r12Detect(t, NewR122UserRestrictionsDetector(), r12Data(types.ACLEntry{
			ObjectDN:   r12TargetDN,
			Trustee:    sidPreWin2000,
			AccessMask: maskReadProp,
			AceType:    "ACCESS_ALLOWED_OBJECT",
			ObjectType: r12RestrictGUID,
		}))
		if f.Count != 0 {
			t.Fatalf("a READ_PROP ACE conveys no privilege, got count=%d", f.Count)
		}
	})

	t.Run("WRITE_PROP granted to a domain principal DOES fire, with entities", func(t *testing.T) {
		// The TRUE positive: a non-Tier-0 domain group can flip
		// userAccountControl bits on a user.
		f := r12Detect(t, NewR122UserRestrictionsDetector(), r12Data(types.ACLEntry{
			ObjectDN:   r12TargetDN,
			Trustee:    sidHelpdesk,
			AccessMask: maskWriteProp,
			AceType:    "ACCESS_ALLOWED_OBJECT",
			ObjectType: r12RestrictGUID,
		}))
		if f.Count != 1 {
			t.Fatalf("WRITE_PROP on User-Account-Restrictions must fire, got count=%d", f.Count)
		}
		if len(f.AffectedEntities) != 1 {
			t.Fatalf("a finding a customer cannot action is not a finding: got %d entities", len(f.AffectedEntities))
		}
		ent := f.AffectedEntities[0]
		if ent.Type != types.EntityTypeACLEntry {
			t.Errorf("entity type = %q, want aclEntry", ent.Type)
		}
		if ent.Trustee == nil || ent.Trustee.SID != sidHelpdesk {
			t.Errorf("entity must name the trustee to revoke, got %+v", ent.Trustee)
		}
		if ent.Target == nil || ent.Target.DN != r12TargetDN {
			t.Errorf("entity must name the target object, got %+v", ent.Target)
		}
	})

	t.Run("Domain Admins is still skipped as a legitimate holder", func(t *testing.T) {
		f := r12Detect(t, NewR122UserRestrictionsDetector(), r12Data(types.ACLEntry{
			ObjectDN:   r12TargetDN,
			Trustee:    sidDomainAdmins,
			AccessMask: maskWriteProp,
			AceType:    "ACCESS_ALLOWED_OBJECT",
			ObjectType: r12RestrictGUID,
		}))
		if f.Count != 0 {
			t.Fatalf("Domain Admins holding the right is expected, got count=%d", f.Count)
		}
	})
}

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

// TestIsWellKnownAdminTrustee covers acceptance §3: the "s-1-5-21-" substring
// excluded every domain principal — the exact population these checks target.
func TestIsWellKnownAdminTrustee(t *testing.T) {
	cases := []struct {
		trustee string
		want    bool
		why     string
	}{
		{sidHelpdesk, false, "ordinary domain group must NOT be treated as a built-in admin"},
		{"S-1-5-21-1234567890-1111111111-2222222222-1105", false, "ordinary domain user"},
		{sidDomainAdmins, true, "Domain Admins (-512)"},
		{"S-1-5-21-1234567890-1111111111-2222222222-519", true, "Enterprise Admins (-519)"},
		{"S-1-5-32-544", true, "BUILTIN\\Administrators"},
		{"S-1-5-18", true, "LOCAL SYSTEM"},
		{"S-1-5-10", true, "SELF"},
		{"S-1-3-0", true, "CREATOR OWNER"},
		{sidPreWin2000, false, "Pre-Windows 2000 Compatible Access is NOT an admin principal"},
		{"S-1-1-0", false, "Everyone"},
		{"DOMAIN\\Domain Admins", true, "friendly-name fallback still works"},
	}
	for _, tc := range cases {
		if got := isWellKnownAdminTrustee(tc.trustee); got != tc.want {
			t.Errorf("isWellKnownAdminTrustee(%q) = %v, want %v — %s", tc.trustee, got, tc.want, tc.why)
		}
	}
}
