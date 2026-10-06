package kerberos

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// TestAdminAsrepRoastableOnDisabledAccount_EnabledAccountExcluded is the
// mirror of TestAdminAsrepRoastable_DisabledAccountExcluded: an enabled
// privileged account carrying DONT_REQUIRE_PREAUTH must not appear here - it
// belongs to AdminAsrepRoastableDetector instead.
func TestAdminAsrepRoastableOnDisabledAccount_EnabledAccountExcluded(t *testing.T) {
	data := &audit.DetectorData{
		IncludeDetails: true,
		ObjectBySID:    objectBySIDWithGroupAsrep(eaSID, eaDN),
		Users: []types.User{
			{
				SAMAccountName:     "active-ea",
				UserAccountControl: types.UACDontRequirePreauth,
				Disabled:           false,
				MemberOf:           []string{eaDN},
			},
			{
				SAMAccountName:     "stale-ea",
				UserAccountControl: types.UACDontRequirePreauth,
				Disabled:           true,
				MemberOf:           []string{eaDN},
			},
		},
	}

	findings := NewAdminAsrepRoastableOnDisabledAccountDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("len(findings) = %d, want 1", len(findings))
	}
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1 (enabled account must be excluded)", findings[0].Count)
	}
	if findings[0].Severity != types.SeverityLow {
		t.Fatalf("Severity = %s, want low", findings[0].Severity)
	}
	if len(findings[0].AffectedEntities) != 1 || findings[0].AffectedEntities[0].SAMAccountName != "stale-ea" {
		t.Fatalf("AffectedEntities = %+v, want only stale-ea", findings[0].AffectedEntities)
	}
}

// TestAdminAsrepRoastableOnDisabledAccount_NotPrivilegedNotFlagged guards the
// negative case: DONT_REQUIRE_PREAUTH on a disabled account alone, without
// membership in a group whose SID carries a types.PrivilegedSIDSuffixes RID
// suffix, must not be flagged.
func TestAdminAsrepRoastableOnDisabledAccount_NotPrivilegedNotFlagged(t *testing.T) {
	ordinaryDN := "CN=GS-Employees,OU=Groups,DC=example,DC=com"
	data := &audit.DetectorData{
		ObjectBySID: objectBySIDWithGroupAsrep("S-1-5-21-1111111111-2222222222-3333333333-9001", ordinaryDN),
		Users: []types.User{
			{
				SAMAccountName:     "ordinary-disabled",
				UserAccountControl: types.UACDontRequirePreauth,
				Disabled:           true,
				MemberOf:           []string{ordinaryDN},
			},
		},
	}

	findings := NewAdminAsrepRoastableOnDisabledAccountDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0", findings[0].Count)
	}
}

// TestAdminAsrepRoastableOnDisabledAccount_WidenedCoverageBySuffix mirrors
// TestAdminAsrepRoastable_WidenedCoverageBySuffix on the disabled side: Key
// Admins (RID -526) membership must be caught by the SID-based match even
// though it was never one of the old seven hardcoded English names.
func TestAdminAsrepRoastableOnDisabledAccount_WidenedCoverageBySuffix(t *testing.T) {
	kaDN := "CN=Key Admins,CN=Users,DC=example,DC=com"
	kaSID := "S-1-5-21-1111111111-2222222222-3333333333-526"
	data := &audit.DetectorData{
		IncludeDetails: true,
		ObjectBySID:    objectBySIDWithGroupAsrep(kaSID, kaDN),
		Users: []types.User{
			{
				SAMAccountName:     "ka-member-disabled",
				UserAccountControl: types.UACDontRequirePreauth,
				Disabled:           true,
				MemberOf:           []string{kaDN},
			},
		},
	}

	findings := NewAdminAsrepRoastableOnDisabledAccountDetector().Detect(context.Background(), data)
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1 (Key Admins is now covered by RID suffix -526)", findings[0].Count)
	}
}
