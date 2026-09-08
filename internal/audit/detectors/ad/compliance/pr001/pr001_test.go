package pr001

import (
	"context"
	"strings"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// both detectors in this package previously cited a nonexistent
// guide "ANSSI PR-001" with fabricated section numbers ("§3.3", "§5.1").
// The real sources are ANSSI PA-022 R27 (dedicated admin accounts, a
// different, non-AD-specific guide) and ANSSI PA-099 R16 (DC OS currency).

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

func TestPR001DCOSObsolete_Detect(t *testing.T) {
	cases := []struct {
		name      string
		dcs       []types.Computer
		wantCount int
	}{
		{
			name:      "modern DC OS -> clean",
			dcs:       []types.Computer{{SAMAccountName: "DC01$", OperatingSystem: "Windows Server 2022 Standard"}},
			wantCount: 0,
		},
		{
			name:      "obsolete DC OS -> flagged",
			dcs:       []types.Computer{{SAMAccountName: "DC01$", OperatingSystem: "Windows Server 2012 R2 Standard"}},
			wantCount: 1,
		},
		{
			// red->green: "2000" was missing from the substring
			// list - the oldest AD-capable OS, EOL since 2010, passed
			// through unflagged.
			name:      "Windows 2000 Server DC -> flagged",
			dcs:       []types.Computer{{SAMAccountName: "DC01$", OperatingSystem: "Windows 2000 Server"}},
			wantCount: 1,
		},
		{
			// Extended-Support-but-not-current: still flagged (R16 asks
			// for staying current, not just "not yet EOL"), but the
			// finding's justification text must not claim 2016's patches
			// are non-existent (checked separately below).
			name:      "Windows Server 2016 DC -> still flagged",
			dcs:       []types.Computer{{SAMAccountName: "DC02$", OperatingSystem: "Windows Server 2016 Standard"}},
			wantCount: 1,
		},
		{
			name:      "unknown OS string -> not flagged",
			dcs:       []types.Computer{{SAMAccountName: "DC01$"}},
			wantCount: 0,
		},
		{
			name:      "multiple DCs, only the obsolete one counted",
			dcs:       []types.Computer{{SAMAccountName: "DC01$", OperatingSystem: "Windows Server 2022 Standard"}, {SAMAccountName: "DC02$", OperatingSystem: "Windows Server 2008 R2 Standard"}},
			wantCount: 1,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data := &audit.DetectorData{DomainControllers: tc.dcs}
			d := NewPR001DCOSObsoleteDetector()
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

// TestPR001DCOSObsolete_2016JustificationNotFalse is a red->green
// test for the 2016 justification bug: before the fix, the description
// claimed Windows Server 2016's "security patches [are] limited or
// non-existent" - false, it receives free security updates under Extended
// Support until January 2027.
func TestPR001DCOSObsolete_2016JustificationNotFalse(t *testing.T) {
	data := &audit.DetectorData{
		DomainControllers: []types.Computer{{SAMAccountName: "DC01$", OperatingSystem: "Windows Server 2016 Standard"}},
	}
	d := NewPR001DCOSObsoleteDetector()
	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count == 0 {
		t.Fatalf("expected a flagged finding, got %+v", findings)
	}
	if strings.Contains(findings[0].Description, "2003/2008/2012/2016") {
		t.Errorf("description still lumps 2016 in with fully-EOL versions under the same 'non-existent patches' claim: %q", findings[0].Description)
	}
	if !strings.Contains(findings[0].Description, "2027") {
		t.Errorf("description should acknowledge 2016's Extended Support end date (Jan 2027), got %q", findings[0].Description)
	}
}

func TestPR001DCOSObsolete_CitesRealSource(t *testing.T) {
	data := &audit.DetectorData{
		DomainControllers: []types.Computer{{SAMAccountName: "DC01$", OperatingSystem: "Windows Server 2012 R2 Standard"}},
	}
	d := NewPR001DCOSObsoleteDetector()
	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count == 0 {
		t.Fatalf("expected a flagged finding, got %+v", findings)
	}
	title, desc := findings[0].Title, findings[0].Description
	if strings.Contains(title, "PR-001") || strings.Contains(desc, "PR-001") {
		t.Errorf("finding still cites the nonexistent guide PR-001: title=%q desc=%q", title, desc)
	}
	if !strings.Contains(desc, "PA-099 R16") {
		t.Errorf("description should cite the real source PA-099 R16, got %q", desc)
	}
}
