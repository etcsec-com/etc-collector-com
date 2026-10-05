package moderate

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// GUIDs below are literals independent from the detector's own map keys:
// the whole point of this file is to catch a mislabeled or drifted GUID,
// which a test built from the same constant could never see.
const (
	wpeUserDN     = "CN=Akira Jackson,OU=IT,DC=example,DC=com"
	wpeComputerDN = "CN=WS-01,OU=Computers,DC=example,DC=com"
	wpeOUDN       = "OU=IT,DC=example,DC=com"

	wpeOrdinaryTrustee   = "S-1-5-21-1234567890-1111111111-2222222222-1108"
	wpeDomainAdminSID    = "S-1-5-21-1234567890-1111111111-2222222222-512" // -512 suffix
	wpeAccountOperators  = "S-1-5-32-548"
	wpeCreatorOwner      = "S-1-3-0"
	wpeSelfSID           = "S-1-5-10"
	wpeUserLogonGUID     = "5f202010-79a5-11d0-9020-00c04fc2d4cf" // User-Logon property set
	wpeScriptPathGUID    = "bf9679a8-0de6-11d0-a285-00aa003049e2" // scriptPath attribute
	wpeProfilePathGUID   = "bf967a05-0de6-11d0-a285-00aa003049e2" // profilePath attribute
	wpeHomeDirectoryGUID = "bf967985-0de6-11d0-a285-00aa003049e2" // homeDirectory attribute

	// The two GUIDs mislabeled by the code before this fix - kept here under
	// their own name (not wpeScriptPathGUID) so T17 documents what they
	// really are.
	wpeOldMislabeledUACGUID         = "bf967a68-0de6-11d0-a285-00aa003049e2" // userAccountControl, was labeled Script-Path
	wpeOldMislabeledDescriptionGUID = "bf967950-0de6-11d0-a285-00aa003049e2" // description, was labeled Home-Directory

	wpeForceChangePasswordGUID = "00299570-246d-11d0-a768-00aa006e0529" // control-access right, owned by the neighbor detector

	wpeWriteProperty = 0x00000020
	wpeReadProperty  = 0x00000010
	wpeControlAccess = 0x00000100
)

func wpeData(aces ...types.ACLEntry) *audit.DetectorData {
	return &audit.DetectorData{
		IncludeDetails: true,
		ACLEntries:     aces,
		ObjectByDN: map[string]*audit.ObjectMeta{
			wpeUserDN:     {DN: wpeUserDN, Name: "Akira Jackson", EntityType: types.EntityTypeUser},
			wpeComputerDN: {DN: wpeComputerDN, Name: "WS-01", EntityType: types.EntityTypeComputer},
			wpeOUDN:       {DN: wpeOUDN, Name: "IT", EntityType: types.EntityTypeOU},
		},
	}
}

func wpeDetect(t *testing.T, data *audit.DetectorData) types.Finding {
	t.Helper()
	findings := NewWritePropertyExtendedDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	return findings[0]
}

// T1-T4: each retained attribute fires on its own, ordinary user target.
func TestWritePropertyExtended_RetainedGUIDsFire(t *testing.T) {
	cases := []struct {
		name string
		guid string
	}{
		{"Script-Path", wpeScriptPathGUID},
		{"Profile-Path", wpeProfilePathGUID},
		{"Home-Directory", wpeHomeDirectoryGUID},
		{"User-Logon property set", wpeUserLogonGUID},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := wpeDetect(t, wpeData(
				types.ACLEntry{ObjectDN: wpeUserDN, Trustee: wpeOrdinaryTrustee, ObjectType: c.guid, AccessMask: wpeWriteProperty, AceType: "ACCESS_ALLOWED_OBJECT"},
			))
			if f.Count != 1 {
				t.Fatalf("%s must fire for an ordinary trustee, got count=%d", c.name, f.Count)
			}
		})
	}
}

// T7: the User-Logon property set on a computer target does not fire -
// AD's own defaultSecurityDescriptor for the computer class grants this to
// the joiner (CREATOR OWNER) on every domain-joined machine.
func TestWritePropertyExtended_ComputerTargetExcluded(t *testing.T) {
	f := wpeDetect(t, wpeData(
		types.ACLEntry{ObjectDN: wpeComputerDN, Trustee: wpeOrdinaryTrustee, ObjectType: wpeUserLogonGUID, AccessMask: wpeWriteProperty, AceType: "ACCESS_ALLOWED_OBJECT"},
	))
	if f.Count != 0 {
		t.Fatalf("logon attributes on a computer object are not a logon path, got count=%d", f.Count)
	}
}

// T8, T9, T11: built-in administrative trustees never fire.
func TestWritePropertyExtended_BuiltinAdminTrusteesExcluded(t *testing.T) {
	cases := []struct {
		name    string
		trustee string
	}{
		{"Domain Admins (-512 suffix)", wpeDomainAdminSID},
		{"Account Operators (S-1-5-32-548)", wpeAccountOperators},
		{"Creator Owner (S-1-3-0)", wpeCreatorOwner},
		{"Self (S-1-5-10)", wpeSelfSID},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := wpeDetect(t, wpeData(
				types.ACLEntry{ObjectDN: wpeUserDN, Trustee: c.trustee, ObjectType: wpeScriptPathGUID, AccessMask: wpeWriteProperty, AceType: "ACCESS_ALLOWED_OBJECT"},
			))
			if f.Count != 0 {
				t.Fatalf("%s is a built-in admin trustee, got count=%d", c.name, f.Count)
			}
		})
	}
}

// T12: a DENY ace grants nothing.
func TestWritePropertyExtended_DenyAceExcluded(t *testing.T) {
	f := wpeDetect(t, wpeData(
		types.ACLEntry{ObjectDN: wpeUserDN, Trustee: wpeOrdinaryTrustee, ObjectType: wpeScriptPathGUID, AccessMask: wpeWriteProperty, AceType: "ACCESS_DENIED_OBJECT"},
	))
	if f.Count != 0 {
		t.Fatalf("a DENY ace grants nothing, got count=%d", f.Count)
	}
}

// T13: an InheritOnly ace does not apply to the object it is set on.
func TestWritePropertyExtended_InheritOnlyExcluded(t *testing.T) {
	f := wpeDetect(t, wpeData(
		types.ACLEntry{ObjectDN: wpeUserDN, Trustee: wpeOrdinaryTrustee, ObjectType: wpeScriptPathGUID, AccessMask: wpeWriteProperty, AceType: "ACCESS_ALLOWED_OBJECT", InheritOnly: true},
	))
	if f.Count != 0 {
		t.Fatalf("INHERIT_ONLY_ACE does not apply to this object, got count=%d", f.Count)
	}
}

// T14: an inherited-but-effective ace (IsInherited without InheritOnly)
// still grants the right on this object and must count.
func TestWritePropertyExtended_InheritedEffectiveAceFires(t *testing.T) {
	f := wpeDetect(t, wpeData(
		types.ACLEntry{ObjectDN: wpeUserDN, Trustee: wpeOrdinaryTrustee, ObjectType: wpeScriptPathGUID, AccessMask: wpeWriteProperty, AceType: "ACCESS_ALLOWED_OBJECT", IsInherited: true, InheritOnly: false},
	))
	if f.Count != 1 {
		t.Fatalf("an inherited but effective ace still grants the right, got count=%d", f.Count)
	}
}

// T15, T16: only the WRITE_PROPERTY bit qualifies - not ReadProperty, not
// CONTROL_ACCESS.
func TestWritePropertyExtended_WrongMaskBitsExcluded(t *testing.T) {
	t.Run("ReadProperty alone does NOT fire", func(t *testing.T) {
		f := wpeDetect(t, wpeData(
			types.ACLEntry{ObjectDN: wpeUserDN, Trustee: wpeOrdinaryTrustee, ObjectType: wpeScriptPathGUID, AccessMask: wpeReadProperty, AceType: "ACCESS_ALLOWED_OBJECT"},
		))
		if f.Count != 0 {
			t.Fatalf("ReadProperty does not grant write, got count=%d", f.Count)
		}
	})
	t.Run("CONTROL_ACCESS alone does NOT fire", func(t *testing.T) {
		f := wpeDetect(t, wpeData(
			types.ACLEntry{ObjectDN: wpeUserDN, Trustee: wpeOrdinaryTrustee, ObjectType: wpeScriptPathGUID, AccessMask: wpeControlAccess, AceType: "ACCESS_ALLOWED_OBJECT"},
		))
		if f.Count != 0 {
			t.Fatalf("CONTROL_ACCESS is not WRITE_PROPERTY, got count=%d", f.Count)
		}
	})
}

// T17: the two GUIDs the code used to mislabel (userAccountControl as
// "Script-Path", description as "Home-Directory") no longer fire here -
// userAccountControl is SERVER_TRUST_ACCOUNT_RIGHT's job, description grants
// no elevation.
func TestWritePropertyExtended_MislabeledGUIDsNoLongerFire(t *testing.T) {
	t.Run("userAccountControl (old Script-Path label)", func(t *testing.T) {
		f := wpeDetect(t, wpeData(
			types.ACLEntry{ObjectDN: wpeUserDN, Trustee: wpeOrdinaryTrustee, ObjectType: wpeOldMislabeledUACGUID, AccessMask: wpeWriteProperty, AceType: "ACCESS_ALLOWED_OBJECT"},
		))
		if f.Count != 0 {
			t.Fatalf("userAccountControl is SERVER_TRUST_ACCOUNT_RIGHT's job, got count=%d", f.Count)
		}
	})
	t.Run("description (old Home-Directory label)", func(t *testing.T) {
		f := wpeDetect(t, wpeData(
			types.ACLEntry{ObjectDN: wpeUserDN, Trustee: wpeOrdinaryTrustee, ObjectType: wpeOldMislabeledDescriptionGUID, AccessMask: wpeWriteProperty, AceType: "ACCESS_ALLOWED_OBJECT"},
		))
		if f.Count != 0 {
			t.Fatalf("description grants no elevation by itself, got count=%d", f.Count)
		}
	})
}

// T18: User-Force-Change-Password is a control-access right, not an
// attribute; it is ACL_USER_FORCE_CHANGE_PASSWORD's and ANSSI_R12_1's job.
func TestWritePropertyExtended_ForceChangePasswordNotOwned(t *testing.T) {
	t.Run("CONTROL_ACCESS grant (realistic usage) does NOT fire", func(t *testing.T) {
		f := wpeDetect(t, wpeData(
			types.ACLEntry{ObjectDN: wpeUserDN, Trustee: wpeOrdinaryTrustee, ObjectType: wpeForceChangePasswordGUID, AccessMask: wpeControlAccess, AceType: "ACCESS_ALLOWED"},
		))
		if f.Count != 0 {
			t.Fatalf("User-Force-Change-Password belongs to the neighbor detector, got count=%d", f.Count)
		}
	})
	t.Run("WRITE_PROPERTY grant does NOT fire either - the GUID is absent from the map", func(t *testing.T) {
		f := wpeDetect(t, wpeData(
			types.ACLEntry{ObjectDN: wpeUserDN, Trustee: wpeOrdinaryTrustee, ObjectType: wpeForceChangePasswordGUID, AccessMask: wpeWriteProperty, AceType: "ACCESS_ALLOWED_OBJECT"},
		))
		if f.Count != 0 {
			t.Fatalf("00299570 must not be reintroduced into the monitored set, got count=%d", f.Count)
		}
	})
}

// T19: two qualifying ACEs on the same target count once in Count, twice in
// TotalInstances.
func TestWritePropertyExtended_SameTargetDedupedInCount(t *testing.T) {
	f := wpeDetect(t, wpeData(
		types.ACLEntry{ObjectDN: wpeUserDN, Trustee: wpeOrdinaryTrustee, ObjectType: wpeScriptPathGUID, AccessMask: wpeWriteProperty, AceType: "ACCESS_ALLOWED_OBJECT"},
		types.ACLEntry{ObjectDN: wpeUserDN, Trustee: wpeOrdinaryTrustee, ObjectType: wpeUserLogonGUID, AccessMask: wpeWriteProperty, AceType: "ACCESS_ALLOWED_OBJECT"},
	))
	if f.Count != 1 {
		t.Fatalf("expected 1 unique target, got count=%d", f.Count)
	}
	if f.TotalInstances != 2 {
		t.Fatalf("expected 2 total instances, got %d", f.TotalInstances)
	}
}

// T20: a target of any other class (OU, group, domain...) is not counted,
// even when it carries a qualifying ACE.
func TestWritePropertyExtended_NonUserNonComputerTargetExcluded(t *testing.T) {
	f := wpeDetect(t, wpeData(
		types.ACLEntry{ObjectDN: wpeOUDN, Trustee: wpeOrdinaryTrustee, ObjectType: wpeScriptPathGUID, AccessMask: wpeWriteProperty, AceType: "ACCESS_ALLOWED_OBJECT"},
	))
	if f.Count != 0 {
		t.Fatalf("an OU target is not a logon attribute question, got count=%d", f.Count)
	}
}

// T-L3: an ACE that passes every other filter (grant, not inherit-only,
// WRITE_PROPERTY, a monitored GUID, not a built-in admin trustee) but whose
// ObjectDN is absent from data.ObjectByDN must not be counted - meta==nil
// means the target's class cannot be confirmed as User, and the computer
// exclusion below it cannot be evaluated either, so it must fail closed
// rather than assume User.
// Verified by mutation (in the detector's Detect, write-property-extended.go,
// changing `if meta == nil || meta.EntityType != types.EntityTypeUser {
// continue }` to `if meta != nil && meta.EntityType != types.EntityTypeUser {
// continue }`, dropping the nil-check from the guard) during development:
// this test alone caught it, going red before the fix was reverted.
func TestWritePropertyExtended_UnknownObjectDNExcluded(t *testing.T) {
	const wpeUnknownDN = "CN=Ghost,OU=IT,DC=example,DC=com" // deliberately absent from wpeData's ObjectByDN
	f := wpeDetect(t, wpeData(
		types.ACLEntry{ObjectDN: wpeUnknownDN, Trustee: wpeOrdinaryTrustee, ObjectType: wpeScriptPathGUID, AccessMask: wpeWriteProperty, AceType: "ACCESS_ALLOWED_OBJECT"},
	))
	if f.Count != 0 {
		t.Fatalf("an ObjectDN absent from ObjectByDN must not be counted (class cannot be confirmed), got count=%d", f.Count)
	}
}

// Runtime Description must match the generated Doc() - cataloggen regenerates
// Doc() from this exact string, so a drift here means a stale catalog.
func TestWritePropertyExtended_DescriptionMatchesDoc(t *testing.T) {
	d := NewWritePropertyExtendedDetector()
	f := wpeDetect(t, wpeData(
		types.ACLEntry{ObjectDN: wpeUserDN, Trustee: wpeOrdinaryTrustee, ObjectType: wpeScriptPathGUID, AccessMask: wpeWriteProperty, AceType: "ACCESS_ALLOWED_OBJECT"},
	))
	if f.Description != d.Doc().Description {
		t.Fatalf("runtime Description and Doc() have drifted apart:\nruntime: %q\nDoc():   %q", f.Description, d.Doc().Description)
	}
}
