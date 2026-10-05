package obsolete

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

func TestObsoleteOS2003_CanonicalStringFires(t *testing.T) {
	data := &audit.DetectorData{
		IncludeDetails: true,
		Computers: []types.Computer{
			{DN: "CN=OLDSRV,DC=contoso,DC=com", OperatingSystem: "Windows Server 2003"},
		},
	}
	findings := NewObsoleteOS2003Detector().Detect(context.Background(), data)
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1", findings[0].Count)
	}
	if got := findings[0].AffectedEntities[0].DN; got != "CN=OLDSRV,DC=contoso,DC=com" {
		t.Fatalf("affected DN = %q, want CN=OLDSRV,DC=contoso,DC=com", got)
	}
}

func TestObsoleteOS2003_NearNeighborNotFlagged(t *testing.T) {
	data := &audit.DetectorData{
		Computers: []types.Computer{
			{DN: "CN=WKS01,DC=contoso,DC=com", OperatingSystem: "Windows 10"},
		},
	}
	findings := NewObsoleteOS2003Detector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0: Windows 10 must not be flagged as Server 2003", findings[0].Count)
	}
}

func TestObsoleteOS2003_EmptyOSIgnored(t *testing.T) {
	data := &audit.DetectorData{
		Computers: []types.Computer{
			{DN: "CN=NOOS,DC=contoso,DC=com", OperatingSystem: ""},
			{DN: "CN=OLDSRV,DC=contoso,DC=com", OperatingSystem: "Windows Server 2003"},
		},
	}
	findings := NewObsoleteOS2003Detector().Detect(context.Background(), data)
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1: empty OperatingSystem must be ignored, not counted", findings[0].Count)
	}
}

func TestObsoleteOS2003_CaseInsensitiveStillFires(t *testing.T) {
	data := &audit.DetectorData{
		Computers: []types.Computer{
			{DN: "CN=OLDSRV,DC=contoso,DC=com", OperatingSystem: "windows server 2003"},
		},
	}
	findings := NewObsoleteOS2003Detector().Detect(context.Background(), data)
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1: match must be case-insensitive", findings[0].Count)
	}
}

// TestObsoleteOS2003_MixedListCountMatchesEntities also pins that this
// detector, unlike COMPUTER_OS_OBSOLETE_2008, does NOT exclude an "R2"
// variant: "Windows Server 2003 R2" still fires (the R2 exclusion only
// exists in the 2008 detector's condition).
func TestObsoleteOS2003_MixedListCountMatchesEntities(t *testing.T) {
	data := &audit.DetectorData{
		IncludeDetails: true,
		Computers: []types.Computer{
			{DN: "CN=SRV1,DC=contoso,DC=com", OperatingSystem: "Windows Server 2003"},
			{DN: "CN=SRV2,DC=contoso,DC=com", OperatingSystem: "Windows Server 2003 R2 Standard"},
			{DN: "CN=WKS1,DC=contoso,DC=com", OperatingSystem: "Windows 11 Enterprise"},
		},
	}
	findings := NewObsoleteOS2003Detector().Detect(context.Background(), data)
	if findings[0].Count != 2 {
		t.Fatalf("Count = %d, want 2 (SRV1 and SRV2, R2 is not excluded for 2003)", findings[0].Count)
	}
	dns := map[string]bool{}
	for _, e := range findings[0].AffectedEntities {
		dns[e.DN] = true
	}
	if !dns["CN=SRV1,DC=contoso,DC=com"] || !dns["CN=SRV2,DC=contoso,DC=com"] {
		t.Fatalf("affected entities = %v, want SRV1 and SRV2", findings[0].AffectedEntities)
	}
}
