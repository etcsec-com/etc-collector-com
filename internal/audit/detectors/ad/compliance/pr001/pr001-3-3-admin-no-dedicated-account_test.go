package pr001

import (
	"context"
	"strings"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// this detector previously cited a nonexistent guide "ANSSI PR-001" with a
// fabricated section number ("§3.3"). The real source is ANSSI PA-022 R27
// (dedicated admin accounts, a different, non-AD-specific guide).

func TestPR001AdminHasNormalAccount_Detect(t *testing.T) {
	cases := []struct {
		name      string
		users     []types.User
		wantCount int
	}{
		{
			name: "admin shares EmployeeID with a non-admin account -> dedicated account, clean",
			users: []types.User{
				{SAMAccountName: "j.dupont", EmployeeID: "E123", AdminCount: false},
				{SAMAccountName: "adm-j.dupont", EmployeeID: "E123", AdminCount: true, ObjectSID: "S-1-5-21-1-2-3-1001"},
			},
			wantCount: 0,
		},
		{
			name: "admin with no matching non-admin EmployeeID -> flagged",
			users: []types.User{
				{SAMAccountName: "adm-nodedicated", EmployeeID: "E999", AdminCount: true, ObjectSID: "S-1-5-21-1-2-3-1002"},
			},
			wantCount: 1,
		},
		{
			name: "admin with empty EmployeeID -> flagged",
			users: []types.User{
				{SAMAccountName: "adm-noeid", AdminCount: true, ObjectSID: "S-1-5-21-1-2-3-1003"},
			},
			wantCount: 1,
		},
		{
			name: "built-in Administrator (RID 500) exempted",
			users: []types.User{
				{SAMAccountName: "Administrator", AdminCount: true, ObjectSID: "S-1-5-21-1-2-3-500"},
			},
			wantCount: 0,
		},
		{
			name: "disabled admin account -> not counted",
			users: []types.User{
				{SAMAccountName: "adm-disabled", AdminCount: true, Disabled: true, ObjectSID: "S-1-5-21-1-2-3-1004"},
			},
			wantCount: 0,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data := &audit.DetectorData{Users: tc.users}
			d := NewPR001AdminHasNormalAccountDetector()
			findings := d.Detect(context.Background(), data)
			if len(findings) != 1 {
				t.Fatalf("expected 1 finding struct, got %d", len(findings))
			}
			if findings[0].Count != tc.wantCount {
				t.Errorf("Count = %d, want %d", findings[0].Count, tc.wantCount)
			}
		})
	}
}

func TestPR001AdminHasNormalAccount_CitesRealSource(t *testing.T) {
	data := &audit.DetectorData{
		Users: []types.User{
			{SAMAccountName: "adm-nodedicated", EmployeeID: "E999", AdminCount: true, ObjectSID: "S-1-5-21-1-2-3-1002"},
		},
	}
	d := NewPR001AdminHasNormalAccountDetector()
	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count == 0 {
		t.Fatalf("expected a flagged finding, got %+v", findings)
	}
	title, desc := findings[0].Title, findings[0].Description
	if strings.Contains(title, "PR-001") || strings.Contains(desc, "PR-001") {
		t.Errorf("finding still cites the nonexistent guide PR-001: title=%q desc=%q", title, desc)
	}
	if !strings.Contains(desc, "PA-022 R27") {
		t.Errorf("description should cite the real source PA-022 R27, got %q", desc)
	}
}
