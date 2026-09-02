package password

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// T_031 — the detector keeps flagging exactly the same accounts; only what it
// carries changes. The pre-fix behaviour attached the verbatim description, so
// the alert saying "there is a password in this field" shipped the password.

// corpus mixes three synthetic descriptions with accounts that must NOT
// fire, so a change in matching behaviour shows up as a count change.
func corpus() []types.User {
	return []types.User{
		// --- must fire (the three live DC01 cases) ---
		{DN: "CN=doe.jane,DC=example,DC=com", SAMAccountName: "doe.jane", Description: "pwd=Sp1ng2001! (temp account)"},
		{DN: "CN=roe.john,DC=example,DC=com", SAMAccountName: "roe.john", Description: "pwd=Xk9#mQ2w! (temp account)"},
		{DN: "CN=poe.alex,DC=example,DC=com", SAMAccountName: "poe.alex", Description: "Temp pwd: Sp1ng2001! - a changer"},
		// --- must fire (the remaining patterns) ---
		{DN: "CN=svc.legacy,DC=example,DC=com", SAMAccountName: "svc.legacy", Description: "password = Tr0ub4dor"},
		{DN: "CN=svc.fr,DC=example,DC=com", SAMAccountName: "svc.fr", Description: "motdepasse: Hiver2026"},
		{DN: "CN=old.acct,DC=example,DC=com", SAMAccountName: "old.acct", Description: "reset to Password123"},
		{DN: "CN=tmp.acct,DC=example,DC=com", SAMAccountName: "tmp.acct", Description: "pass: qwerty"},
		// --- must NOT fire ---
		{DN: "CN=alice,DC=example,DC=com", SAMAccountName: "alice", Description: "Service account for the backup job"},
		{DN: "CN=bob,DC=example,DC=com", SAMAccountName: "bob", Description: "Password policy owner"},
		{DN: "CN=carol,DC=example,DC=com", SAMAccountName: "carol", Description: ""},
		{DN: "CN=dave,DC=example,DC=com", SAMAccountName: "dave"},
	}
}

// wantFlagged is the exact set of accounts the pre-fix detector flagged on this
// corpus, verified against the original predicate.
var wantFlagged = []string{
	"doe.jane", "roe.john", "poe.alex",
	"svc.legacy", "svc.fr", "old.acct", "tmp.acct",
}

func detect(t *testing.T, includeDetails bool) types.Finding {
	t.Helper()
	findings := NewInDescriptionDetector().Detect(context.Background(), &audit.DetectorData{
		IncludeDetails: includeDetails,
		Users:          corpus(),
	})
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	return findings[0]
}

// TestInDescription_FiresOnTheSameAccounts is the non-regression guard: same
// count, same accounts, unchanged severity.
func TestInDescription_FiresOnTheSameAccounts(t *testing.T) {
	f := detect(t, true)

	if f.Count != len(wantFlagged) {
		t.Fatalf("count = %d, want %d — the detector must flag the same accounts as before", f.Count, len(wantFlagged))
	}
	if f.Severity != types.SeverityHigh {
		t.Errorf("severity = %q, want high", f.Severity)
	}
	if len(f.AffectedEntities) != len(wantFlagged) {
		t.Fatalf("entities = %d, want %d", len(f.AffectedEntities), len(wantFlagged))
	}

	got := make(map[string]bool, len(f.AffectedEntities))
	for _, e := range f.AffectedEntities {
		got[e.SAMAccountName] = true
	}
	for _, want := range wantFlagged {
		if !got[want] {
			t.Errorf("account %q is no longer flagged — a true positive disappeared", want)
		}
	}
	for _, notWanted := range []string{"alice", "bob", "carol", "dave"} {
		if got[notWanted] {
			t.Errorf("account %q must not be flagged", notWanted)
		}
	}
}

// TestInDescription_NeverShipsTheSecret covers the acceptance criterion: a
// cleartext password in, none of it out of the serialised finding.
func TestInDescription_NeverShipsTheSecret(t *testing.T) {
	f := detect(t, true)

	raw, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	out := string(raw)

	// Every credential present in the corpus must be absent from the payload.
	for _, secret := range []string{
		"Sp1ng2001!", "Xk9#mQ2w!", "Tr0ub4dor", "Hiver2026", "Password123", "qwerty",
	} {
		if strings.Contains(out, secret) {
			t.Errorf("the finding shipped the credential %q it was reporting: %s", secret, out)
		}
	}

	// And the raw description text must not survive either — this finding is
	// about the description, so it carries none of it.
	for _, desc := range []string{"pwd=", "motdepasse:", "password ="} {
		if strings.Contains(out, desc) {
			t.Errorf("the finding shipped raw description text %q: %s", desc, out)
		}
	}
}

// TestInDescription_NamesThePatternInstead — what replaces the secret has to be
// useful: the administrator learns which kind of credential to look for.
func TestInDescription_NamesThePatternInstead(t *testing.T) {
	f := detect(t, true)

	byAccount := map[string]string{}
	for _, e := range f.AffectedEntities {
		byAccount[e.SAMAccountName] = e.Description
	}

	cases := map[string]string{
		"doe.jane":   "pwd-assignment",
		"svc.legacy": "password-assignment",
		"svc.fr":     "motdepasse-assignment",
		"old.acct":   "known-weak-password",
		"tmp.acct":   "pass-assignment",
	}
	for account, wantPattern := range cases {
		desc, ok := byAccount[account]
		if !ok {
			t.Errorf("account %q missing from the entities", account)
			continue
		}
		if !strings.Contains(desc, wantPattern) {
			t.Errorf("account %q: description = %q, want it to name %q", account, desc, wantPattern)
		}
		if !strings.HasPrefix(desc, "matched credential pattern:") {
			t.Errorf("account %q: description = %q, want the pattern-name form", account, desc)
		}
	}
}

// TestInDescription_CountIsIndependentOfDetails — the count must not depend on
// whether details are included, so a customer with details off sees the same
// number of exposed accounts.
func TestInDescription_CountIsIndependentOfDetails(t *testing.T) {
	withDetails := detect(t, true)
	withoutDetails := detect(t, false)

	if withDetails.Count != withoutDetails.Count {
		t.Errorf("count differs with details on/off: %d vs %d", withDetails.Count, withoutDetails.Count)
	}
	if len(withoutDetails.AffectedEntities) != 0 {
		t.Errorf("details off must carry no entities, got %d", len(withoutDetails.AffectedEntities))
	}
}
