package types

import (
	"encoding/json"
	"strings"
	"testing"
)

// T_031 / B_024 — PASSWORD_IN_DESCRIPTION reported accounts whose description
// holds a credential, and shipped that description verbatim: on DC01 the report
// carried `pwd=Sp1ng2001!`, `pwd=Xk9#mQ2w!` and `Temp pwd: Sp1ng2001!` to the
// cloud, attached to the very finding saying "there is a password here".

// sampleDescriptions are synthetic strings shaped like the ones this detector
// must catch — never real observations — the regression this ticket exists to prevent.
var sampleDescriptions = []string{
	"pwd=Sp1ng2001! (temp account)",
	"pwd=Xk9#mQ2w! (temp account)",
	"Temp pwd: Sp1ng2001! - a changer",
}

// TestUserEntityNeverShipsACredential is the core acceptance test: a cleartext
// password goes in, and none of it comes out of the serialised entity.
func TestUserEntityNeverShipsACredential(t *testing.T) {
	secrets := []string{"Sp1ng2001!", "Xk9#mQ2w!"}

	for _, desc := range sampleDescriptions {
		u := User{
			DN:             "CN=doe.jane,OU=IT,DC=example,DC=com",
			SAMAccountName: "doe.jane",
			Description:    desc,
		}
		raw, err := json.Marshal(UserToAffectedEntity(&u))
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		out := string(raw)

		for _, secret := range secrets {
			if strings.Contains(out, secret) {
				t.Errorf("description %q leaked the credential %q into the payload: %s", desc, secret, out)
			}
		}
		if !strings.Contains(out, SecretRedactionMarker) {
			t.Errorf("description %q should carry %s, got: %s", desc, SecretRedactionMarker, out)
		}
		// The account itself must still be identifiable — redaction must not
		// cost the report its actionability.
		if !strings.Contains(out, "doe.jane") {
			t.Errorf("the account must still be named, got: %s", out)
		}
	}
}

// TestRedactSecretsKeepsLegitimateContext — redaction replaces the credential
// span, not the whole attribute, so a description stays useful for triage.
func TestRedactSecretsKeepsLegitimateContext(t *testing.T) {
	cases := []struct {
		in       string
		wantKeep string // substring that must survive
		wantGone string // substring that must not
	}{
		{"Service account for backups, pwd=Ete2026!", "Service account for backups", "Ete2026!"},
		{"Compte temporaire motdepasse: Hiver2026", "Compte temporaire", "Hiver2026"},
		{"legacy app, password = Tr0ub4dor", "legacy app", "Tr0ub4dor"},
		{"see P@ssw0rd policy doc", "see", "P@ssw0rd"},
	}
	for _, tc := range cases {
		got := RedactSecrets(tc.in)
		if !strings.Contains(got, tc.wantKeep) {
			t.Errorf("RedactSecrets(%q) = %q, should keep %q", tc.in, got, tc.wantKeep)
		}
		if strings.Contains(got, tc.wantGone) {
			t.Errorf("RedactSecrets(%q) = %q, must not keep %q", tc.in, got, tc.wantGone)
		}
	}
}

// TestRedactSecretsLeavesOrdinaryTextAlone — the redactor must not mangle the
// descriptions of the thousands of accounts that hold no secret.
func TestRedactSecretsLeavesOrdinaryTextAlone(t *testing.T) {
	untouched := []string{
		"",
		"Service account for the backup job",
		"Compte de service — supervision Nagios",
		"Password policy owner",   // mentions passwords, assigns none
		"pass through account",    // "pass" without an assignment
		"Migrated from OLDDOMAIN", //nolint:misspell
	}
	for _, s := range untouched {
		if got := RedactSecrets(s); got != s {
			t.Errorf("RedactSecrets(%q) = %q, want it unchanged", s, got)
		}
	}
}

// TestMatchSecretPatternsNamesTheShape — the detector reports WHICH kind of
// credential was found; the names must be stable and free of the matched text.
func TestMatchSecretPatternsNamesTheShape(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"pwd=Sp1ng2001! (temp account)", []string{"pwd-assignment"}},
		// "password:" does not also match the pass-assignment pattern: after
		// "pass" comes "word", not a separator.
		{"password: hunter2", []string{"password-assignment"}},
		{"pass: hunter2", []string{"pass-assignment"}},
		{"motdepasse = Ete2026", []string{"motdepasse-assignment"}},
		{"P@ssw0rd", []string{"known-weak-password"}},
		{"Password123", []string{"known-weak-password"}},
		{"Service account for backups", nil},
		{"", nil},
	}
	for _, tc := range cases {
		got := MatchSecretPatterns(tc.in)
		if len(got) != len(tc.want) {
			t.Errorf("MatchSecretPatterns(%q) = %v, want %v", tc.in, got, tc.want)
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("MatchSecretPatterns(%q) = %v, want %v", tc.in, got, tc.want)
				break
			}
			// A pattern name must never quote what it matched.
			if strings.Contains(tc.in, got[i]) && got[i] != "" {
				t.Errorf("pattern name %q echoes the input", got[i])
			}
		}
	}
}

// TestDetectionAndRedactionCannotDrift pins the invariant behind putting the
// pattern table next to the mappers: anything the detector flags is redacted by
// the mapper. A redactor that misses what the detector reports is the original
// bug all over again.
func TestDetectionAndRedactionCannotDrift(t *testing.T) {
	for _, desc := range append(sampleDescriptions,
		"password=x", "pass:y", "motdepasse=z", "P@ssw0rd", "Password123") {
		if len(MatchSecretPatterns(desc)) == 0 {
			t.Errorf("%q should be detected", desc)
			continue
		}
		if got := RedactSecrets(desc); got == desc {
			t.Errorf("%q is detected as a credential but was not redacted (got %q)", desc, got)
		}
	}
}

// TestComputerAndGroupDescriptionsAreRedactedToo — the same free-text attribute
// is copied by all three entity mappers, so the leak was never user-only.
func TestComputerAndGroupDescriptionsAreRedactedToo(t *testing.T) {
	c := Computer{DN: "CN=WS-01,DC=example,DC=com", SAMAccountName: "WS-01$", Description: "local admin pwd=Ete2026!"}
	g := Group{DN: "CN=Ops,DC=example,DC=com", SAMAccountName: "Ops", Description: "shared password: Ete2026!"}

	for name, ent := range map[string]AffectedEntity{
		"computer": ComputerToAffectedEntity(&c),
		"group":    GroupToAffectedEntity(&g),
	} {
		raw, err := json.Marshal(ent)
		if err != nil {
			t.Fatalf("%s: marshal: %v", name, err)
		}
		if strings.Contains(string(raw), "Ete2026!") {
			t.Errorf("%s entity leaked the credential: %s", name, raw)
		}
	}
}
