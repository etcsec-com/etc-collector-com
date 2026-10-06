package ldap

import (
	"testing"
	"time"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// --- trustAuthChangeFromMetadata: literal XML captured on a real lab DC ---

// labTrustAuthOutgoingXML is the exact msDS-ReplAttributeMetaData value
// captured for a live TDO's trustAuthOutgoing entry, byte for byte - not
// retyped from a table, the actual XML blob returned by the directory
// (identifying values replaced with fictitious ones for publication).
// trustAuthIncoming was recorded as identical except for pszAttributeName.
const labTrustAuthOutgoingXML = `<DS_REPL_ATTR_META_DATA>
	<pszAttributeName>trustAuthOutgoing</pszAttributeName>
	<dwVersion>1</dwVersion>
	<ftimeLastOriginatingChange>2026-09-16T06:39:42Z</ftimeLastOriginatingChange>
	<uuidLastOriginatingDsaInvocationID>00000000-0000-0000-0000-000000000001</uuidLastOriginatingDsaInvocationID>
	<usnOriginatingChange>2922938</usnOriginatingChange>
	<usnLocalChange>2922938</usnLocalChange>
	<pszLastOriginatingDsaDN>CN=NTDS Settings,CN=DC1,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=example,DC=com</pszLastOriginatingDsaDN>
</DS_REPL_ATTR_META_DATA>`

func TestTrustAuthChangeFromMetadata_LabLiteral(t *testing.T) {
	entry := parseReplMetadataXML(labTrustAuthOutgoingXML)
	entries := []audit.ReplMetadataEntry{entry}

	got := trustAuthChangeFromMetadata(entries, "trustAuthOutgoing")
	want := time.Date(2026, 9, 16, 6, 39, 42, 0, time.UTC)
	if !got.Equal(want) {
		t.Fatalf("trustAuthChangeFromMetadata(trustAuthOutgoing) = %v, want %v", got, want)
	}
	if entry.Version != 1 {
		t.Fatalf("dwVersion = %d, want 1 (never rotated since TDO creation)", entry.Version)
	}
}

// TestTrustAuthChangeFromMetadata_MissingEntry covers the case where the
// requested direction's attribute simply isn't present in the metadata list
// (e.g. a one-way trust that never had trustAuthIncoming written) - must
// return zero, not a synthetic date.
func TestTrustAuthChangeFromMetadata_MissingEntry(t *testing.T) {
	entries := []audit.ReplMetadataEntry{
		{AttributeName: "trustAuthOutgoing", LastChangeTime: time.Date(2026, 9, 16, 6, 39, 42, 0, time.UTC), Version: 1},
		{AttributeName: "whenCreated", LastChangeTime: time.Date(2026, 9, 16, 6, 39, 42, 0, time.UTC), Version: 1},
	}
	got := trustAuthChangeFromMetadata(entries, "trustAuthIncoming")
	if !got.IsZero() {
		t.Fatalf("trustAuthChangeFromMetadata(trustAuthIncoming) = %v, want zero (attribute absent)", got)
	}
}

// TestTrustAuthChangeFromMetadata_UnreadableValue covers a malformed/unreadable
// XML value (e.g. a truncated or corrupted read) - parseReplMetadataXML
// yields a zero LastChangeTime, and the selection must propagate that zero
// rather than treat AttributeName presence alone as a valid date.
func TestTrustAuthChangeFromMetadata_UnreadableValue(t *testing.T) {
	xml := `<DS_REPL_ATTR_META_DATA><pszAttributeName>trustAuthOutgoing</pszAttributeName>` +
		`<ftimeLastOriginatingChange>not-a-timestamp</ftimeLastOriginatingChange></DS_REPL_ATTR_META_DATA>`
	entry := parseReplMetadataXML(xml)
	entries := []audit.ReplMetadataEntry{entry}

	got := trustAuthChangeFromMetadata(entries, "trustAuthOutgoing")
	if !got.IsZero() {
		t.Fatalf("trustAuthChangeFromMetadata with unreadable timestamp = %v, want zero", got)
	}
}

// --- trustAccountPwdLastSet: flatName -> sAMAccountName join (MS-ADTS 6.1.6.8) ---

func TestTrustAccountPwdLastSet_Joins(t *testing.T) {
	want := time.Date(2026, 9, 16, 6, 39, 42, 0, time.UTC)
	accounts := map[string]time.Time{"PARTNER$": want}
	got := trustAccountPwdLastSet("PARTNER", accounts)
	if !got.Equal(want) {
		t.Fatalf("trustAccountPwdLastSet(PARTNER) = %v, want %v", got, want)
	}
}

func TestTrustAccountPwdLastSet_CaseInsensitive(t *testing.T) {
	want := time.Date(2026, 9, 16, 6, 39, 42, 0, time.UTC)
	accounts := map[string]time.Time{"partner$": want}
	got := trustAccountPwdLastSet("PARTNER", accounts)
	if !got.Equal(want) {
		t.Fatalf("trustAccountPwdLastSet(PARTNER) against lowercase account = %v, want %v", got, want)
	}
}

func TestTrustAccountPwdLastSet_NoMatch(t *testing.T) {
	accounts := map[string]time.Time{"PARTNERX$": time.Now()}
	got := trustAccountPwdLastSet("PARTNER", accounts)
	if !got.IsZero() {
		t.Fatalf("trustAccountPwdLastSet(PARTNER) against PARTNERX$ = %v, want zero (no prefix match)", got)
	}
}

func TestTrustAccountPwdLastSet_EmptyFlatName(t *testing.T) {
	accounts := map[string]time.Time{"$": time.Now()}
	got := trustAccountPwdLastSet("", accounts)
	if !got.IsZero() {
		t.Fatalf("trustAccountPwdLastSet(\"\") = %v, want zero even against a literal \"$\" account", got)
	}
}

// --- resolveOutgoingPasswordDate / resolveIncomingPasswordDate: per-direction preference ---

func TestResolveOutgoingPasswordDate_MetadataPresent(t *testing.T) {
	meta := time.Date(2026, 9, 16, 6, 39, 42, 0, time.UTC)
	date, source := resolveOutgoingPasswordDate(meta)
	if !date.Equal(meta) || source != "replmetadata" {
		t.Fatalf("resolveOutgoingPasswordDate = (%v, %q), want (%v, replmetadata)", date, source, meta)
	}
}

func TestResolveOutgoingPasswordDate_NoMetadata(t *testing.T) {
	date, source := resolveOutgoingPasswordDate(time.Time{})
	if !date.IsZero() || source != "" {
		t.Fatalf("resolveOutgoingPasswordDate(zero) = (%v, %q), want (zero, \"\")", date, source)
	}
}

func TestResolveIncomingPasswordDate_MetadataOnly(t *testing.T) {
	meta := time.Date(2026, 9, 16, 6, 39, 42, 0, time.UTC)
	date, source := resolveIncomingPasswordDate(meta, time.Time{})
	if !date.Equal(meta) || source != "replmetadata" {
		t.Fatalf("resolveIncomingPasswordDate(meta only) = (%v, %q), want (%v, replmetadata)", date, source, meta)
	}
}

func TestResolveIncomingPasswordDate_AccountOnly(t *testing.T) {
	acct := time.Date(2026, 9, 16, 6, 39, 42, 0, time.UTC)
	date, source := resolveIncomingPasswordDate(time.Time{}, acct)
	if !date.Equal(acct) || source != "trust_account" {
		t.Fatalf("resolveIncomingPasswordDate(account only) = (%v, %q), want (%v, trust_account)", date, source, acct)
	}
}

// TestResolveIncomingPasswordDate_BothPresent_MetadataWins is the direct
// literal-fixture test for the incoming-direction preference order: when
// both a metadata reading and an account pwdLastSet exist, the metadata
// date must win, even though the account date is more recent in this
// fixture - picking "most recent" instead of "metadata always" would
// silently pass a naive test but gets the wrong secret (the account's
// pwdLastSet can lag a later TDO-side rotation). Verified by mutation
// (swapping the preference to account-first) during development: this
// test alone caught it, going red before the fix was reverted.
func TestResolveIncomingPasswordDate_BothPresent_MetadataWins(t *testing.T) {
	meta := time.Date(2026, 9, 16, 6, 39, 42, 0, time.UTC)     // older
	acct := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)      // newer, must NOT win
	date, source := resolveIncomingPasswordDate(meta, acct)
	if source != "replmetadata" {
		t.Fatalf("resolveIncomingPasswordDate(both) source = %q, want replmetadata (metadata must win)", source)
	}
	if !date.Equal(meta) {
		t.Fatalf("resolveIncomingPasswordDate(both) date = %v, want %v (metadata date, not the newer account date)", date, meta)
	}
}

func TestResolveIncomingPasswordDate_Neither(t *testing.T) {
	date, source := resolveIncomingPasswordDate(time.Time{}, time.Time{})
	if !date.IsZero() || source != "" {
		t.Fatalf("resolveIncomingPasswordDate(neither) = (%v, %q), want (zero, \"\") - silence, not a guess", date, source)
	}
}

// --- trustSecretDates: GetTrusts' per-direction wiring ---

// TestTrustSecretDates_OutgoingAndIncomingNeverSwapped (T-MV2) pins the
// wiring GetTrusts depends on, end to end: from each direction's own
// msDS-ReplAttributeMetaData attribute (never the other's) through to the
// matching *types.Trust field (never the other field). trustAuthOutgoing is
// fixed at J-100, trustAuthIncoming at J-5 - two different dates, so a swap
// at either step is visible in either direction, not masked by a
// coincidental match. Asserting on trust's fields directly (rather than on
// intermediate return values) is what closes the permutation surface:
// trustSecretDates now writes into *types.Trust itself, so this is the only
// test that can catch a swap at that write.
// Verified by mutation during development, two independent mutants, each
// caught by this test alone, then reverted:
//   - swapping the "trustAuthOutgoing"/"trustAuthIncoming" literals inside
//     trustSecretDates (the original T-MV2 mutant);
//   - swapping which resolved value is written to which trust field inside
//     trustSecretDates (the equivalent of the lead's measurement, which
//     swapped the two fields at the old call-site assignment in client.go -
//     a call site that no longer exists to swap).
func TestTrustSecretDates_OutgoingAndIncomingNeverSwapped(t *testing.T) {
	now := time.Date(2026, 9, 27, 0, 0, 0, 0, time.UTC)
	outgoingWant := now.AddDate(0, 0, -100)
	incomingWant := now.AddDate(0, 0, -5)
	entries := []audit.ReplMetadataEntry{
		{AttributeName: "trustAuthOutgoing", LastChangeTime: outgoingWant, Version: 1},
		{AttributeName: "trustAuthIncoming", LastChangeTime: incomingWant, Version: 1},
	}

	var trust types.Trust
	trustSecretDates(&trust, entries, "PARTNER", nil)

	if !trust.OutgoingPasswordDate.Equal(outgoingWant) || trust.OutgoingPasswordSource != "replmetadata" {
		t.Fatalf("OutgoingPasswordDate/Source = (%v, %q), want (%v, replmetadata) - the J-100 date, never J-5", trust.OutgoingPasswordDate, trust.OutgoingPasswordSource, outgoingWant)
	}
	if !trust.IncomingPasswordDate.Equal(incomingWant) || trust.IncomingPasswordSource != "replmetadata" {
		t.Fatalf("IncomingPasswordDate/Source = (%v, %q), want (%v, replmetadata) - the J-5 date, never J-100", trust.IncomingPasswordDate, trust.IncomingPasswordSource, incomingWant)
	}
}
