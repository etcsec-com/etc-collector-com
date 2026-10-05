package obsolete

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

func TestObsoleteOSXP_CanonicalStringFires(t *testing.T) {
	data := &audit.DetectorData{
		IncludeDetails: true,
		Computers: []types.Computer{
			{DN: "CN=OLDWKS,DC=contoso,DC=com", OperatingSystem: "Windows XP Professional"},
		},
	}
	findings := NewObsoleteOSXPDetector().Detect(context.Background(), data)
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1", findings[0].Count)
	}
	if got := findings[0].AffectedEntities[0].DN; got != "CN=OLDWKS,DC=contoso,DC=com" {
		t.Fatalf("affected DN = %q, want CN=OLDWKS,DC=contoso,DC=com", got)
	}
}

func TestObsoleteOSXP_NearNeighborNotFlagged(t *testing.T) {
	data := &audit.DetectorData{
		Computers: []types.Computer{
			{DN: "CN=WKS01,DC=contoso,DC=com", OperatingSystem: "Windows 10"},
		},
	}
	findings := NewObsoleteOSXPDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0: Windows 10 must not be flagged as XP", findings[0].Count)
	}
}

func TestObsoleteOSXP_EmptyOSIgnored(t *testing.T) {
	data := &audit.DetectorData{
		Computers: []types.Computer{
			{DN: "CN=NOOS,DC=contoso,DC=com", OperatingSystem: ""},
			{DN: "CN=OLDWKS,DC=contoso,DC=com", OperatingSystem: "Windows XP Professional"},
		},
	}
	findings := NewObsoleteOSXPDetector().Detect(context.Background(), data)
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1: empty OperatingSystem must be ignored, not counted", findings[0].Count)
	}
}

func TestObsoleteOSXP_CaseInsensitiveStillFires(t *testing.T) {
	data := &audit.DetectorData{
		Computers: []types.Computer{
			{DN: "CN=OLDWKS,DC=contoso,DC=com", OperatingSystem: "windows xp professional"},
		},
	}
	findings := NewObsoleteOSXPDetector().Detect(context.Background(), data)
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1: match must be case-insensitive", findings[0].Count)
	}
}

func TestObsoleteOSXP_MixedListCountMatchesEntities(t *testing.T) {
	data := &audit.DetectorData{
		IncludeDetails: true,
		Computers: []types.Computer{
			{DN: "CN=WKS1,DC=contoso,DC=com", OperatingSystem: "Windows XP Professional"},
			{DN: "CN=WKS2,DC=contoso,DC=com", OperatingSystem: "Windows XP Home"},
			{DN: "CN=WKS3,DC=contoso,DC=com", OperatingSystem: "Windows 11 Enterprise"},
		},
	}
	findings := NewObsoleteOSXPDetector().Detect(context.Background(), data)
	if findings[0].Count != 2 {
		t.Fatalf("Count = %d, want 2 (WKS1 and WKS2)", findings[0].Count)
	}
	dns := map[string]bool{}
	for _, e := range findings[0].AffectedEntities {
		dns[e.DN] = true
	}
	if !dns["CN=WKS1,DC=contoso,DC=com"] || !dns["CN=WKS2,DC=contoso,DC=com"] {
		t.Fatalf("affected entities = %v, want WKS1 and WKS2", findings[0].AffectedEntities)
	}
}

// TestObsoleteOSXP_DoubleSpaceNotFlagged pins a known coverage gap: the
// regex requires the contiguous substring "Windows XP". A value with
// irregular spacing between the two words does not match, so a real XP
// machine whose OperatingSystem was entered with an extra space silently
// evades this detector. This test documents the gap as expected current
// behavior, not a bug to fix here.
func TestObsoleteOSXP_DoubleSpaceNotFlagged(t *testing.T) {
	data := &audit.DetectorData{
		Computers: []types.Computer{
			{DN: "CN=WKS01,DC=contoso,DC=com", OperatingSystem: "Windows  XP Professional"},
		},
	}
	findings := NewObsoleteOSXPDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0: a double space breaks the contiguous \"Windows XP\" match (known gap)", findings[0].Count)
	}
}
