package password

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

const testChangePasswordGUID = types.GUIDChangePassword

// TestCannotChange_DenyEveryoneFlagged covers the documented state with only
// the Everyone Deny ACE present. Real plant/revert on DC01 established that
// AD always sets both trustees together via the supported mechanism, but the
// access-check reasoning in the Detect doc comment holds for either alone -
// this pins that this detector does not require both.
func TestCannotChange_DenyEveryoneFlagged(t *testing.T) {
	data := &audit.DetectorData{
		IncludeDetails: true,
		Users:          []types.User{{SAMAccountName: "locked-out", DN: "CN=locked-out,DC=example,DC=com"}},
		ACLEntries: []types.ACLEntry{
			{ObjectDN: "CN=locked-out,DC=example,DC=com", Trustee: sidEveryone, AceType: "ACCESS_DENIED_OBJECT", ObjectType: testChangePasswordGUID},
		},
	}

	findings := NewCannotChangeDetector().Detect(context.Background(), data)
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1", findings[0].Count)
	}
}

// TestCannotChange_DenySelfFlagged mirrors the above for the SELF trustee
// alone, the other half of the OR condition.
func TestCannotChange_DenySelfFlagged(t *testing.T) {
	data := &audit.DetectorData{
		Users: []types.User{{SAMAccountName: "locked-out", DN: "CN=locked-out,DC=example,DC=com"}},
		ACLEntries: []types.ACLEntry{
			{ObjectDN: "CN=locked-out,DC=example,DC=com", Trustee: sidSelf, AceType: "ACCESS_DENIED_OBJECT", ObjectType: testChangePasswordGUID},
		},
	}

	findings := NewCannotChangeDetector().Detect(context.Background(), data)
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1", findings[0].Count)
	}
}

// TestCannotChange_BothDenyACEsCountOnce is the grouping requirement: the
// documented plant mechanism (ADUC's "User cannot change password"
// checkbox) always produces TWO Deny ACEs (Everyone + Self) on one account.
// The counter must count the account once, not the ACE twice.
func TestCannotChange_BothDenyACEsCountOnce(t *testing.T) {
	data := &audit.DetectorData{
		Users: []types.User{{SAMAccountName: "locked-out", DN: "CN=locked-out,DC=example,DC=com"}},
		ACLEntries: []types.ACLEntry{
			{ObjectDN: "CN=locked-out,DC=example,DC=com", Trustee: sidEveryone, AceType: "ACCESS_DENIED_OBJECT", ObjectType: testChangePasswordGUID},
			{ObjectDN: "CN=locked-out,DC=example,DC=com", Trustee: sidSelf, AceType: "ACCESS_DENIED_OBJECT", ObjectType: testChangePasswordGUID},
		},
	}

	findings := NewCannotChangeDetector().Detect(context.Background(), data)
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1 (one account, two ACEs)", findings[0].Count)
	}
}

// TestCannotChange_AllowACENotFlagged guards the default AD DS state: two
// ACCESS_ALLOWED_OBJECT ACEs on the same right, same trustees, must not
// trigger the finding.
func TestCannotChange_AllowACENotFlagged(t *testing.T) {
	data := &audit.DetectorData{
		Users: []types.User{{SAMAccountName: "ordinary", DN: "CN=ordinary,DC=example,DC=com"}},
		ACLEntries: []types.ACLEntry{
			{ObjectDN: "CN=ordinary,DC=example,DC=com", Trustee: sidEveryone, AceType: "ACCESS_ALLOWED_OBJECT", ObjectType: testChangePasswordGUID},
			{ObjectDN: "CN=ordinary,DC=example,DC=com", Trustee: sidSelf, AceType: "ACCESS_ALLOWED_OBJECT", ObjectType: testChangePasswordGUID},
		},
	}

	findings := NewCannotChangeDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0", findings[0].Count)
	}
}

// TestCannotChange_DenyOnDifferentRightNotFlagged guards the ObjectType
// filter: a Deny ACE for the two documented trustees, but on an unrelated
// extended right, must not trigger.
func TestCannotChange_DenyOnDifferentRightNotFlagged(t *testing.T) {
	data := &audit.DetectorData{
		Users: []types.User{{SAMAccountName: "unrelated", DN: "CN=unrelated,DC=example,DC=com"}},
		ACLEntries: []types.ACLEntry{
			{ObjectDN: "CN=unrelated,DC=example,DC=com", Trustee: sidEveryone, AceType: "ACCESS_DENIED_OBJECT", ObjectType: types.GUIDForceChangePassword},
		},
	}

	findings := NewCannotChangeDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0", findings[0].Count)
	}
}

// TestCannotChange_DenyOtherTrusteeNotFlagged guards the trustee filter: a
// Deny ACE on the right GUID, but for neither Everyone nor SELF, must not
// trigger - it restricts some other principal, not the account's own
// self-change path.
func TestCannotChange_DenyOtherTrusteeNotFlagged(t *testing.T) {
	data := &audit.DetectorData{
		Users: []types.User{{SAMAccountName: "unrelated", DN: "CN=unrelated,DC=example,DC=com"}},
		ACLEntries: []types.ACLEntry{
			{ObjectDN: "CN=unrelated,DC=example,DC=com", Trustee: "S-1-5-21-1-2-3-1234", AceType: "ACCESS_DENIED_OBJECT", ObjectType: testChangePasswordGUID},
		},
	}

	findings := NewCannotChangeDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0", findings[0].Count)
	}
}
