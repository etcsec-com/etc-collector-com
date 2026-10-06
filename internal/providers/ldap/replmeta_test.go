package ldap

import (
	"strings"
	"testing"
	"time"
)

// TestParseReplMetadataXML_TrailingZ covers a shared-parser bug affecting
// DISPLAY_SPECIFIER_CHANGES / PRIVILEGED_GROUP_MEMBER_CHANGES /
// SCHEMA_SD_RECENT_CHANGE (three detectors sharing this parser): AD's real
// ftimeLastOriginatingChange carries a trailing "Z" (measured live on DC01,
// e.g. 2025-11-17T13:01:17Z on CN=409,CN=DisplaySpecifiers), but the layout
// "2006-01-02T15:04:05" does not consume it, so time.Parse always errored
// and LastChangeTime stayed the zero value - every detector gated on
// "!LastChangeTime.IsZero()" was structurally blind, never a false
// positive, never a true one either.
func TestParseReplMetadataXML_TrailingZ(t *testing.T) {
	xml := `<DS_REPL_ATTR_META_DATA><pszAttributeName>description</pszAttributeName>` +
		`<ftimeLastOriginatingChange>2025-11-17T13:01:17Z</ftimeLastOriginatingChange>` +
		`<dwVersion>3</dwVersion></DS_REPL_ATTR_META_DATA>`

	entry := parseReplMetadataXML(xml)

	if entry.LastChangeTime.IsZero() {
		t.Fatal("LastChangeTime is zero - the trailing Z on a real AD timestamp was not parsed")
	}
	if entry.LastChangeTime.Year() != 2025 || entry.LastChangeTime.Month() != 11 || entry.LastChangeTime.Day() != 17 {
		t.Fatalf("LastChangeTime = %v, want 2025-11-17T13:01:17Z", entry.LastChangeTime)
	}
}

// TestParseReplMetadataXML_NoTrailingZ guards the legacy layout (no Z)
// against regression, since GetReplValueMetadata shares the same parser.
func TestParseReplMetadataXML_NoTrailingZ(t *testing.T) {
	xml := `<DS_REPL_ATTR_META_DATA><pszAttributeName>description</pszAttributeName>` +
		`<ftimeLastOriginatingChange>2025-11-17T13:01:17</ftimeLastOriginatingChange>` +
		`<dwVersion>3</dwVersion></DS_REPL_ATTR_META_DATA>`

	entry := parseReplMetadataXML(xml)

	if entry.LastChangeTime.IsZero() {
		t.Fatal("LastChangeTime is zero for the legacy (no-Z) layout - must still be supported")
	}
}

// TestParseReplValueMetadataXML_TrailingZ covers PRIVILEGED_GROUP_MEMBER_CHANGES:
// reproduces the real DC01 payload for
// msDS-ReplValueMetaData (CN=Domain Admins membership changes), which
// carries a trailing literal "Z" on ftimeLastOriginatingChange. Before the
// fix, GetReplValueMetadata's `!t.IsZero()` filter (client.go) dropped
// every entry, leaving engine.go's PrivilegedGroupMemberChanges map
// permanently empty regardless of real membership churn.
func TestParseReplValueMetadataXML_TrailingZ(t *testing.T) {
	raw := `<DS_REPL_VALUE_META_DATA>` +
		`<pszObjectDn>CN=Domain Admins,CN=Users,DC=example,DC=com</pszObjectDn>` +
		`<ftimeLastOriginatingChange>2026-01-31T01:42:54Z</ftimeLastOriginatingChange>` +
		`</DS_REPL_VALUE_META_DATA>`

	dn, changeTime := parseReplValueMetadataXML(raw)

	if !strings.HasPrefix(dn, "CN=Domain Admins") {
		t.Fatalf("dn = %q, want prefix CN=Domain Admins", dn)
	}
	if changeTime.IsZero() {
		t.Fatal("trailing-Z timestamp must parse, not silently zero out")
	}
	want := time.Date(2026, 1, 31, 1, 42, 54, 0, time.UTC)
	if !changeTime.UTC().Equal(want) {
		t.Fatalf("changeTime = %v, want %v", changeTime.UTC(), want)
	}
}
