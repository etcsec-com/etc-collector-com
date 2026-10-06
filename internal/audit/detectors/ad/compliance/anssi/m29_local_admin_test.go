package anssi

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
)

// TestM29_NameBasedPrincipal_Recognized is a red->green test for the
// name-vs-SID bug: MS-GPSB's ABNF for a [Group Membership] entry allows the
// principal to be written as a bare group name ("Administrators__Members=")
// instead of a SID ("*S-1-5-32-544__Members="). Before the fix, only the SID
// form was matched, so a GPO authored with the name form was invisible and
// M29 fired even though the group genuinely was restricted.
func TestM29_NameBasedPrincipal_Recognized(t *testing.T) {
	d := NewM29LocalAdminNotRestrictedDetector()
	data := &audit.DetectorData{
		GPOPolicies: map[string]*audit.GPOPolicy{
			"{gpo}": {
				RestrictedGroups: []audit.RestrictedGroupSpec{
					{GroupSID: "Administrators", MembersSIDs: []string{"S-1-5-21-1-2-3-500"}},
				},
			},
		},
	}
	findings := d.Detect(context.Background(), data)
	if len(findings) != 0 {
		t.Fatalf("expected no finding (name-based principal restricts local Administrators), got %+v", findings)
	}
}

// TestM29_ExplicitEmptyMembers_NotFlagged is a red->green test for
// the nil-vs-absent bug: parseGroupMembership's parseSIDList("") returns nil
// for a value-less "*S-1-5-32-544__Members=" line (explicitly restricting
// local Administrators to NOBODY, the strictest possible hardening) - before
// the fix, that was indistinguishable from "never configured" and flagged as
// an M29 violation.
func TestM29_ExplicitEmptyMembers_NotFlagged(t *testing.T) {
	d := NewM29LocalAdminNotRestrictedDetector()
	data := &audit.DetectorData{
		GPOPolicies: map[string]*audit.GPOPolicy{
			"{gpo}": {
				RestrictedGroups: []audit.RestrictedGroupSpec{
					{GroupSID: builtinAdministratorsSID, MembersSIDs: nil},
				},
			},
		},
	}
	findings := d.Detect(context.Background(), data)
	if len(findings) != 0 {
		t.Fatalf("expected no finding (explicit empty Members restricts local Administrators to nobody), got %+v", findings)
	}
}

// TestM29_NoRestrictedGroupsAtAll_StillFlagged is the sanity check that the
// fix didn't turn the detector into a no-op: a domain with GPO data but no
// [Group Membership] entry for BUILTIN\Administrators at all must still be
// flagged.
func TestM29_NoRestrictedGroupsAtAll_StillFlagged(t *testing.T) {
	d := NewM29LocalAdminNotRestrictedDetector()
	data := &audit.DetectorData{
		GPOPolicies: map[string]*audit.GPOPolicy{
			"{gpo}": {RestrictedGroups: nil},
		},
	}
	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 1 {
		t.Fatalf("expected exactly 1 finding with Count=1, got %+v", findings)
	}
}

// TestM29_UnrelatedRestrictedGroup_StillFlagged confirms restricting a
// different group (not BUILTIN\Administrators) doesn't satisfy M29.
func TestM29_UnrelatedRestrictedGroup_StillFlagged(t *testing.T) {
	d := NewM29LocalAdminNotRestrictedDetector()
	data := &audit.DetectorData{
		GPOPolicies: map[string]*audit.GPOPolicy{
			"{gpo}": {
				RestrictedGroups: []audit.RestrictedGroupSpec{
					{GroupSID: "S-1-5-32-551", MembersSIDs: []string{"S-1-5-21-1-2-3-1000"}}, // Backup Operators
				},
			},
		},
	}
	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 1 {
		t.Fatalf("expected exactly 1 finding with Count=1, got %+v", findings)
	}
}
