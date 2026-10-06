package obsolete

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

func TestObsoleteOSNT_WindowsNTBranchFires(t *testing.T) {
	data := &audit.DetectorData{
		IncludeDetails: true,
		Computers: []types.Computer{
			{DN: "CN=LEGACYNT,DC=contoso,DC=com", OperatingSystem: "Windows NT Server 4.0"},
		},
	}
	findings := NewObsoleteOSNTDetector().Detect(context.Background(), data)
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1", findings[0].Count)
	}
	if got := findings[0].AffectedEntities[0].DN; got != "CN=LEGACYNT,DC=contoso,DC=com" {
		t.Fatalf("affected DN = %q, want CN=LEGACYNT,DC=contoso,DC=com", got)
	}
}

// TestObsoleteOSNT_Windows2000BranchFires exercises the OR condition's
// second branch independently of the first: "windows nt" and
// "windows 2000" are two distinct substrings, and a computer matching only
// one of them must still fire.
func TestObsoleteOSNT_Windows2000BranchFires(t *testing.T) {
	data := &audit.DetectorData{
		Computers: []types.Computer{
			{DN: "CN=LEGACY2000,DC=contoso,DC=com", OperatingSystem: "Windows 2000 Server"},
		},
	}
	findings := NewObsoleteOSNTDetector().Detect(context.Background(), data)
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1: the \"windows 2000\" branch must fire independently", findings[0].Count)
	}
}

func TestObsoleteOSNT_NearNeighborNotFlagged(t *testing.T) {
	data := &audit.DetectorData{
		Computers: []types.Computer{
			{DN: "CN=WKS01,DC=contoso,DC=com", OperatingSystem: "Windows 10"},
		},
	}
	findings := NewObsoleteOSNTDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0: Windows 10 must not be flagged", findings[0].Count)
	}
}

func TestObsoleteOSNT_EmptyOSIgnored(t *testing.T) {
	data := &audit.DetectorData{
		Computers: []types.Computer{
			{DN: "CN=NOOS,DC=contoso,DC=com", OperatingSystem: ""},
			{DN: "CN=LEGACYNT,DC=contoso,DC=com", OperatingSystem: "Windows NT Server 4.0"},
		},
	}
	findings := NewObsoleteOSNTDetector().Detect(context.Background(), data)
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1: empty OperatingSystem must be ignored, not counted", findings[0].Count)
	}
}

func TestObsoleteOSNT_CaseInsensitiveStillFires(t *testing.T) {
	data := &audit.DetectorData{
		Computers: []types.Computer{
			{DN: "CN=LEGACYNT,DC=contoso,DC=com", OperatingSystem: "WINDOWS NT SERVER 4.0"},
		},
	}
	findings := NewObsoleteOSNTDetector().Detect(context.Background(), data)
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1: match must be case-insensitive", findings[0].Count)
	}
}

func TestObsoleteOSNT_MixedListCountMatchesEntities(t *testing.T) {
	data := &audit.DetectorData{
		IncludeDetails: true,
		Computers: []types.Computer{
			{DN: "CN=NT1,DC=contoso,DC=com", OperatingSystem: "Windows NT Server 4.0"},
			{DN: "CN=W2K1,DC=contoso,DC=com", OperatingSystem: "Windows 2000 Server"},
			{DN: "CN=WKS1,DC=contoso,DC=com", OperatingSystem: "Windows 11 Enterprise"},
			{DN: "CN=WKS2,DC=contoso,DC=com", OperatingSystem: ""},
		},
	}
	findings := NewObsoleteOSNTDetector().Detect(context.Background(), data)
	if findings[0].Count != 2 {
		t.Fatalf("Count = %d, want 2 (NT1 and W2K1)", findings[0].Count)
	}
	dns := map[string]bool{}
	for _, e := range findings[0].AffectedEntities {
		dns[e.DN] = true
	}
	if !dns["CN=NT1,DC=contoso,DC=com"] || !dns["CN=W2K1,DC=contoso,DC=com"] {
		t.Fatalf("affected entities = %v, want NT1 and W2K1", findings[0].AffectedEntities)
	}
}
