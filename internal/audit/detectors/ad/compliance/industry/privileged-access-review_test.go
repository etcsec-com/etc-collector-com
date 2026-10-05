package industry

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

func TestPrivilegedAccessReview_Detect(t *testing.T) {
	now := time.Date(2026, 9, 2, 0, 0, 0, 0, time.UTC)
	stale := now.AddDate(0, 0, -91)
	recent := now.AddDate(0, 0, -10)

	cases := []struct {
		name      string
		data      *audit.DetectorData
		wantCount int
	}{
		{
			name: "stale enabled Domain Admin -> flagged",
			data: &audit.DetectorData{
				Now: now,
				Users: []types.User{
					{SAMAccountName: "backup_admin", MemberOf: []string{"CN=Domain Admins,CN=Users,DC=test,DC=local"}, LastLogon: stale},
				},
			},
			wantCount: 1,
		},
		{
			name: "recently active Domain Admin -> not flagged",
			data: &audit.DetectorData{
				Now: now,
				Users: []types.User{
					{SAMAccountName: "admin", MemberOf: []string{"CN=Domain Admins,CN=Users,DC=test,DC=local"}, LastLogon: recent},
				},
			},
			wantCount: 0,
		},
		{
			// flipped from "not flagged". A privileged account that
			// has NEVER logged on is at least as much a review candidate as
			// a stale one - the old exclusion hid exactly the accounts most
			// worth reviewing (standing, unused privileged credentials).
			name: "never-logged-on Domain Admin (LastLogon zero) -> flagged",
			data: &audit.DetectorData{
				Now: now,
				Users: []types.User{
					{SAMAccountName: "administrator2", MemberOf: []string{"CN=Domain Admins,CN=Users,DC=test,DC=local"}},
				},
			},
			wantCount: 1,
		},
		{
			name: "stale but disabled Domain Admin -> not flagged",
			data: &audit.DetectorData{
				Now: now,
				Users: []types.User{
					{SAMAccountName: "old_admin", MemberOf: []string{"CN=Domain Admins,CN=Users,DC=test,DC=local"}, LastLogon: stale, Disabled: true},
				},
			},
			wantCount: 0,
		},
		{
			name: "stale non-admin user -> not flagged",
			data: &audit.DetectorData{
				Now: now,
				Users: []types.User{
					{SAMAccountName: "regular_user", LastLogon: stale},
				},
			},
			wantCount: 0,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := NewPrivilegedAccessReviewDetector()
			findings := d.Detect(context.Background(), tc.data)
			if len(findings) != 1 {
				t.Fatalf("expected exactly 1 finding struct, got %d", len(findings))
			}
			if findings[0].Count != tc.wantCount {
				t.Errorf("Count = %d, want %d", findings[0].Count, tc.wantCount)
			}
		})
	}
}

// TestPrivilegedAccessReview_RoleScopedAdministratorsGroup_NotFlagged is the
// red->green test for the bare "administrators" substring bug: before
// the fix, membership in role-scoped Builtin groups like "Hyper-V
// Administrators" or "DHCP Administrators" - which carry no domain-wide
// privilege - was wrongly counted as admin-group membership.
func TestPrivilegedAccessReview_RoleScopedAdministratorsGroup_NotFlagged(t *testing.T) {
	now := time.Date(2026, 9, 2, 0, 0, 0, 0, time.UTC)
	stale := now.AddDate(0, 0, -91)

	data := &audit.DetectorData{
		Now: now,
		Users: []types.User{
			{SAMAccountName: "hv_op", MemberOf: []string{"CN=Hyper-V Administrators,CN=Builtin,DC=test,DC=local"}, LastLogon: stale},
		},
	}
	d := NewPrivilegedAccessReviewDetector()
	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding struct, got %d", len(findings))
	}
	if findings[0].Count != 0 {
		t.Errorf("Count = %d, want 0 - Hyper-V Administrators is not a domain-wide privileged group", findings[0].Count)
	}
}

// TestPrivilegedAccessReview_BuiltinAdministrators_StillFlagged confirms the
// exact-CN fix still catches the real BUILTIN\Administrators group.
func TestPrivilegedAccessReview_BuiltinAdministrators_StillFlagged(t *testing.T) {
	now := time.Date(2026, 9, 2, 0, 0, 0, 0, time.UTC)
	stale := now.AddDate(0, 0, -91)

	data := &audit.DetectorData{
		Now: now,
		Users: []types.User{
			{SAMAccountName: "local_admin", MemberOf: []string{"CN=Administrators,CN=Builtin,DC=test,DC=local"}, LastLogon: stale},
		},
	}
	d := NewPrivilegedAccessReviewDetector()
	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding struct, got %d", len(findings))
	}
	if findings[0].Count != 1 {
		t.Errorf("Count = %d, want 1 - BUILTIN\\Administrators is the real target group", findings[0].Count)
	}
}

// TestPrivilegedAccessReview_LastLogonTimestampMoreRecent_NotFlagged is the
// red->green test for the non-replicated lastLogon bug: a user whose
// lastLogon (this DC's own view) is stale but whose lastLogonTimestamp
// (replicated, reflects activity possibly seen by another DC) is recent must
// not be flagged.
func TestPrivilegedAccessReview_LastLogonTimestampMoreRecent_NotFlagged(t *testing.T) {
	now := time.Date(2026, 9, 2, 0, 0, 0, 0, time.UTC)
	stale := now.AddDate(0, 0, -91)
	recent := now.AddDate(0, 0, -5)

	data := &audit.DetectorData{
		Now: now,
		Users: []types.User{
			{SAMAccountName: "multi_dc_admin", MemberOf: []string{"CN=Domain Admins,CN=Users,DC=test,DC=local"}, LastLogon: stale, LastLogonTimestamp: recent},
		},
	}
	d := NewPrivilegedAccessReviewDetector()
	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding struct, got %d", len(findings))
	}
	if findings[0].Count != 0 {
		t.Errorf("Count = %d, want 0 - lastLogonTimestamp (replicated) shows recent activity even though this DC's own lastLogon is stale", findings[0].Count)
	}
}

// TestPrivilegedAccessReview_NoteFormatsCountAsDecimal guards against a
// regression of the string(rune(n)) bug: that conversion
// renders n as a Unicode code point (e.g. 15 -> the ASCII "Shift In" control
// character), not as the decimal text "15", whenever more than 10 stale
// admins are found.
func TestPrivilegedAccessReview_NoteFormatsCountAsDecimal(t *testing.T) {
	now := time.Date(2026, 9, 2, 0, 0, 0, 0, time.UTC)
	stale := now.AddDate(0, 0, -91)

	users := make([]types.User, 0, 15)
	for i := 0; i < 15; i++ {
		users = append(users, types.User{
			SAMAccountName: "stale_admin",
			MemberOf:       []string{"CN=Domain Admins,CN=Users,DC=test,DC=local"},
			LastLogon:      stale,
		})
	}

	d := NewPrivilegedAccessReviewDetector()
	findings := d.Detect(context.Background(), &audit.DetectorData{Now: now, Users: users})
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding struct, got %d", len(findings))
	}

	note, ok := findings[0].Details["note"].(string)
	if !ok {
		t.Fatalf("expected a string note when stale count exceeds 10, got %#v", findings[0].Details["note"])
	}
	if !strings.Contains(note, "15") {
		t.Errorf("note = %q, want it to contain the decimal count %q", note, "15")
	}
}
