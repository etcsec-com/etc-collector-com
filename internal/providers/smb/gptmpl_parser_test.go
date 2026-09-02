package smb

import "testing"

// TestParseRegistryValues_RestrictRemoteSAM is the T_132/D2 regression test.
// RestrictRemoteSAM is configured as a Security Option in GptTmpl.inf's
// [Registry Values] section, which Windows writes as REG_SZ (type 1) — an
// SDDL string, never a REG_DWORD. parseRegistryValues used to filter to
// type-4 entries only and had no case for it at all, so this path was
// invisible regardless of GPO content.
func TestParseRegistryValues_RestrictRemoteSAM(t *testing.T) {
	sec := map[string]string{
		`MACHINE\System\CurrentControlSet\Control\Lsa\RestrictRemoteSam`: `1,"O:BAG:BAD:(A;;RC;;;BA)"`,
	}

	rs := parseRegistryValues(sec)

	if rs == nil {
		t.Fatal("parseRegistryValues returned nil for a section containing RestrictRemoteSam")
	}
	if rs.RestrictRemoteSAM == nil {
		t.Fatal("RestrictRemoteSAM not populated")
	}
	if got, want := *rs.RestrictRemoteSAM, `O:BAG:BAD:(A;;RC;;;BA)`; got != want {
		t.Fatalf("RestrictRemoteSAM = %q, want %q (quotes must be stripped)", got, want)
	}
}

// TestParseRegistryValues_DwordEntriesStillWork guards against a regression
// where broadening the type filter (T_132/D2) from "type 4 only" to
// "4, or 1/2 for a couple of string settings" breaks the REG_DWORD path
// every other setting in this function relies on.
func TestParseRegistryValues_DwordEntriesStillWork(t *testing.T) {
	sec := map[string]string{
		`MACHINE\System\CurrentControlSet\Control\Lsa\RunAsPPL`: `4,1`,
	}

	rs := parseRegistryValues(sec)

	if rs == nil || rs.LSARunAsPPL == nil {
		t.Fatal("RunAsPPL (REG_DWORD) not populated")
	}
	if *rs.LSARunAsPPL != 1 {
		t.Fatalf("LSARunAsPPL = %d, want 1", *rs.LSARunAsPPL)
	}
}

// TestParseRegistryValues_UnrecognizedStringIgnored confirms a REG_SZ/
// REG_EXPAND_SZ entry that isn't RestrictRemoteSAM doesn't get misfiled
// into it, and doesn't make the function report found=true on its own.
func TestParseRegistryValues_UnrecognizedStringIgnored(t *testing.T) {
	sec := map[string]string{
		`MACHINE\Some\Unrelated\StringValue`: `1,"whatever"`,
	}

	rs := parseRegistryValues(sec)

	if rs != nil {
		t.Fatalf("expected nil for a section with no recognized entries, got %+v", rs)
	}
}
