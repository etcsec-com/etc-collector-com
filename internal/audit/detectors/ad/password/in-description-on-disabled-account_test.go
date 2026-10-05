package password

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// disabledCorpus mirrors in-description_test.go's corpus structure but uses
// its own literal strings, distinct from the active test's fixtures, so a
// regression specific to the disabled half cannot hide behind the active
// test still passing.
func disabledCorpus() []types.User {
	return []types.User{
		// --- must fire: disabled with a matching pattern ---
		{DN: "CN=legacy.svc,DC=example,DC=com", SAMAccountName: "legacy.svc", Description: "pwd=OldSecret99! (deprovisioned)", Disabled: true},
		{DN: "CN=former.admin,DC=example,DC=com", SAMAccountName: "former.admin", Description: "password = N3verLogin", Disabled: true},
		{DN: "CN=archive.acct,DC=example,DC=com", SAMAccountName: "archive.acct", Description: "motdepasse: Archive2024", Disabled: true},
		// --- must NOT fire: active account, same kind of pattern ---
		{DN: "CN=active.svc,DC=example,DC=com", SAMAccountName: "active.svc", Description: "pwd=StillLive42!"},
		// --- must NOT fire: disabled account, no pattern ---
		{DN: "CN=disabled.clean,DC=example,DC=com", SAMAccountName: "disabled.clean", Description: "Decommissioned 2024", Disabled: true},
		{DN: "CN=disabled.empty,DC=example,DC=com", SAMAccountName: "disabled.empty", Description: "", Disabled: true},
	}
}

var wantFlaggedDisabled = []string{"legacy.svc", "former.admin", "archive.acct"}

func detectDisabled(t *testing.T, includeDetails bool) types.Finding {
	t.Helper()
	findings := NewPasswordInDescriptionOnDisabledAccountDetector().Detect(context.Background(), &audit.DetectorData{
		IncludeDetails: includeDetails,
		Users:          disabledCorpus(),
	})
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	return findings[0]
}

// TestInDescriptionOnDisabledAccount_FiresOnlyOnDisabledWithPattern is the
// non-regression guard for this half: only disabled accounts carrying a
// matching pattern are counted.
func TestInDescriptionOnDisabledAccount_FiresOnlyOnDisabledWithPattern(t *testing.T) {
	f := detectDisabled(t, true)

	if f.Count != len(wantFlaggedDisabled) {
		t.Fatalf("count = %d, want %d", f.Count, len(wantFlaggedDisabled))
	}
	if f.Severity != types.SeverityLow {
		t.Errorf("severity = %q, want low", f.Severity)
	}
	if len(f.AffectedEntities) != len(wantFlaggedDisabled) {
		t.Fatalf("entities = %d, want %d", len(f.AffectedEntities), len(wantFlaggedDisabled))
	}

	got := make(map[string]bool, len(f.AffectedEntities))
	for _, e := range f.AffectedEntities {
		got[e.SAMAccountName] = true
	}
	for _, want := range wantFlaggedDisabled {
		if !got[want] {
			t.Errorf("account %q is not flagged", want)
		}
	}
	for _, notWanted := range []string{"active.svc", "disabled.clean", "disabled.empty"} {
		if got[notWanted] {
			t.Errorf("account %q must not be flagged", notWanted)
		}
	}
}

// TestInDescriptionOnDisabledAccount_ExcludesActiveAccounts is the guard's
// mutation kill: an active account carrying the exact same credential
// pattern must not fire here - it is reported instead, at High, by
// InDescriptionDetector.
func TestInDescriptionOnDisabledAccount_ExcludesActiveAccounts(t *testing.T) {
	data := &audit.DetectorData{
		IncludeDetails: true,
		Users: []types.User{
			{DN: "CN=active.only,DC=example,DC=com", SAMAccountName: "active.only", Description: "pwd=ActiveOnly1!"},
		},
	}
	findings := NewPasswordInDescriptionOnDisabledAccountDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 0 {
		t.Fatalf("an active account with a matching description must not fire in the disabled-account detector, got count=%d", findings[0].Count)
	}
}

// TestInDescriptionOnDisabledAccount_NeverShipsTheSecret covers the same
// non-negotiable contract as the active half: a cleartext password in, none
// of it out of the serialised finding.
func TestInDescriptionOnDisabledAccount_NeverShipsTheSecret(t *testing.T) {
	f := detectDisabled(t, true)

	raw, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	out := string(raw)

	for _, secret := range []string{"OldSecret99!", "N3verLogin", "Archive2024"} {
		if strings.Contains(out, secret) {
			t.Errorf("the finding shipped the credential %q it was reporting: %s", secret, out)
		}
	}
}

// TestInDescriptionOnDisabledAccount_CountIsIndependentOfDetails - the count
// must not depend on whether details are included.
func TestInDescriptionOnDisabledAccount_CountIsIndependentOfDetails(t *testing.T) {
	withDetails := detectDisabled(t, true)
	withoutDetails := detectDisabled(t, false)

	if withDetails.Count != withoutDetails.Count {
		t.Errorf("count differs with details on/off: %d vs %d", withDetails.Count, withoutDetails.Count)
	}
	if len(withoutDetails.AffectedEntities) != 0 {
		t.Errorf("details off must carry no entities, got %d", len(withoutDetails.AffectedEntities))
	}
}

// TestPasswordInDescription_PartitionIsExhaustive covers both detectors
// together: an account with a matching pattern is counted by exactly one of
// the two - active or disabled - never both, never neither.
func TestPasswordInDescription_PartitionIsExhaustive(t *testing.T) {
	users := []types.User{
		{DN: "CN=active-match", SAMAccountName: "active-match", Description: "pwd=Match123!"},
		{DN: "CN=disabled-match", SAMAccountName: "disabled-match", Description: "pwd=Match456!", Disabled: true},
		{DN: "CN=active-clean", SAMAccountName: "active-clean", Description: "no secret here"},
		{DN: "CN=disabled-clean", SAMAccountName: "disabled-clean", Description: "no secret here", Disabled: true},
	}
	data := &audit.DetectorData{Users: users, IncludeDetails: true}

	active := NewInDescriptionDetector().Detect(context.Background(), data)
	disabled := NewPasswordInDescriptionOnDisabledAccountDetector().Detect(context.Background(), data)

	if active[0].Count != 1 {
		t.Fatalf("active half: want 1 (active-match), got %d", active[0].Count)
	}
	if disabled[0].Count != 1 {
		t.Fatalf("disabled half: want 1 (disabled-match), got %d", disabled[0].Count)
	}
}
