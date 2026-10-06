package ldap

import (
	"reflect"
	"sort"
	"testing"
)

// TestParseCSEExtensionNames covers GPO_LAPS_NOT_DEPLOYED
// (false positive, allume_a_tort=true): GetGPOs never requested gPCMachineExtensionNames/
// gPCUserExtensionNames and never assigned types.GPO.CSEGuids, so
// hasLAPSCse() (internal/audit/detectors/ad/gpo/laps-not-deployed.go) always
// saw an empty list and the detector reported "LAPS not deployed" on every
// scan regardless of real state. Real AD format:
// "[{CSE-GUID}{Snapin-GUID}][{CSE-GUID2}{Snapin-GUID2}]..." - bracket groups
// of concatenated {GUID} tokens, no separator inside a group.
func TestParseCSEExtensionNames(t *testing.T) {
	machine := "[{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}]" +
		"[{D76B9641-3288-4f75-942D-087DE603E3EA}{4CFB60C1-FAA6-47F1-89AA-0B18730C9FD3}]"
	user := "[{4BCD6CDE-777B-48B6-9804-43568E23545D}{FF87231B-5select-fake}]"

	got := parseCSEExtensionNames(machine, "")
	want := []string{
		"{827D319E-6EAC-11D2-A4EA-00C04F79F83A}",
		"{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}",
		"{D76B9641-3288-4f75-942D-087DE603E3EA}",
		"{4CFB60C1-FAA6-47F1-89AA-0B18730C9FD3}",
	}
	sort.Strings(got)
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parseCSEExtensionNames(machine) = %v, want %v", got, want)
	}

	// Windows LAPS CSE GUID must be extracted from the user extension names too.
	gotUser := parseCSEExtensionNames("", user)
	found := false
	for _, g := range gotUser {
		if g == "{4BCD6CDE-777B-48B6-9804-43568E23545D}" {
			found = true
		}
	}
	if !found {
		t.Fatalf("parseCSEExtensionNames(userExt) = %v, want it to contain the Windows LAPS CSE GUID", gotUser)
	}
}

// TestParseCSEExtensionNames_Empty guards the no-data case: an empty
// attribute value must not produce a spurious non-nil/non-empty result.
func TestParseCSEExtensionNames_Empty(t *testing.T) {
	got := parseCSEExtensionNames("", "")
	if len(got) != 0 {
		t.Fatalf("parseCSEExtensionNames(\"\", \"\") = %v, want empty", got)
	}
}
