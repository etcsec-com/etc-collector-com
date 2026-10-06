package obsolete

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

func TestObsoleteOSVista_CanonicalStringFires(t *testing.T) {
	data := &audit.DetectorData{
		IncludeDetails: true,
		Computers: []types.Computer{
			{DN: "CN=OLDLAP,DC=contoso,DC=com", OperatingSystem: "Windows Vista Business"},
		},
	}
	findings := NewObsoleteOSVistaDetector().Detect(context.Background(), data)
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1", findings[0].Count)
	}
	if got := findings[0].AffectedEntities[0].DN; got != "CN=OLDLAP,DC=contoso,DC=com" {
		t.Fatalf("affected DN = %q, want CN=OLDLAP,DC=contoso,DC=com", got)
	}
}

func TestObsoleteOSVista_NearNeighborNotFlagged(t *testing.T) {
	data := &audit.DetectorData{
		Computers: []types.Computer{
			{DN: "CN=WKS01,DC=contoso,DC=com", OperatingSystem: "Windows 10"},
		},
	}
	findings := NewObsoleteOSVistaDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0: Windows 10 must not be flagged as Vista", findings[0].Count)
	}
}

func TestObsoleteOSVista_EmptyOSIgnored(t *testing.T) {
	data := &audit.DetectorData{
		Computers: []types.Computer{
			{DN: "CN=NOOS,DC=contoso,DC=com", OperatingSystem: ""},
			{DN: "CN=OLDLAP,DC=contoso,DC=com", OperatingSystem: "Windows Vista Business"},
		},
	}
	findings := NewObsoleteOSVistaDetector().Detect(context.Background(), data)
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1: empty OperatingSystem must be ignored, not counted", findings[0].Count)
	}
}

func TestObsoleteOSVista_CaseInsensitiveStillFires(t *testing.T) {
	data := &audit.DetectorData{
		Computers: []types.Computer{
			{DN: "CN=OLDLAP,DC=contoso,DC=com", OperatingSystem: "windows vista business"},
		},
	}
	findings := NewObsoleteOSVistaDetector().Detect(context.Background(), data)
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1: match must be case-insensitive", findings[0].Count)
	}
}

func TestObsoleteOSVista_MixedListCountMatchesEntities(t *testing.T) {
	data := &audit.DetectorData{
		IncludeDetails: true,
		Computers: []types.Computer{
			{DN: "CN=LAP1,DC=contoso,DC=com", OperatingSystem: "Windows Vista Business"},
			{DN: "CN=LAP2,DC=contoso,DC=com", OperatingSystem: "Windows Vista Ultimate"},
			{DN: "CN=WKS1,DC=contoso,DC=com", OperatingSystem: "Windows 11 Enterprise"},
		},
	}
	findings := NewObsoleteOSVistaDetector().Detect(context.Background(), data)
	if findings[0].Count != 2 {
		t.Fatalf("Count = %d, want 2 (LAP1 and LAP2)", findings[0].Count)
	}
	dns := map[string]bool{}
	for _, e := range findings[0].AffectedEntities {
		dns[e.DN] = true
	}
	if !dns["CN=LAP1,DC=contoso,DC=com"] || !dns["CN=LAP2,DC=contoso,DC=com"] {
		t.Fatalf("affected entities = %v, want LAP1 and LAP2", findings[0].AffectedEntities)
	}
}
