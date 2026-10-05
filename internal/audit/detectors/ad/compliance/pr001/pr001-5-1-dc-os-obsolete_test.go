package pr001

import (
	"context"
	"strings"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// this detector previously cited a nonexistent guide "ANSSI PR-001" with a
// fabricated section number ("§5.1"). The real source is ANSSI PA-099 R16
// (DC OS currency).

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
