package obsolete

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

func TestObsoleteOS2008_CanonicalStringFires(t *testing.T) {
	data := &audit.DetectorData{
		IncludeDetails: true,
		Computers: []types.Computer{
			{DN: "CN=OLDSRV,DC=contoso,DC=com", OperatingSystem: "Windows Server 2008 Standard"},
		},
	}
	findings := NewObsoleteOS2008Detector().Detect(context.Background(), data)
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1", findings[0].Count)
	}
	if got := findings[0].AffectedEntities[0].DN; got != "CN=OLDSRV,DC=contoso,DC=com" {
		t.Fatalf("affected DN = %q, want CN=OLDSRV,DC=contoso,DC=com", got)
	}
}

// TestObsoleteOS2008_R2ExcludedNotFlagged pins the detector's own
// documented boundary: Server 2008 R2 is a different, later-EOL product
// and must not be counted as the plain 2008 finding.
func TestObsoleteOS2008_R2ExcludedNotFlagged(t *testing.T) {
	data := &audit.DetectorData{
		Computers: []types.Computer{
			{DN: "CN=SRV2R2,DC=contoso,DC=com", OperatingSystem: "Windows Server 2008 R2 Standard"},
		},
	}
	findings := NewObsoleteOS2008Detector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0: Server 2008 R2 must be excluded", findings[0].Count)
	}
}

func TestObsoleteOS2008_EmptyOSIgnored(t *testing.T) {
	data := &audit.DetectorData{
		Computers: []types.Computer{
			{DN: "CN=NOOS,DC=contoso,DC=com", OperatingSystem: ""},
			{DN: "CN=OLDSRV,DC=contoso,DC=com", OperatingSystem: "Windows Server 2008 Standard"},
		},
	}
	findings := NewObsoleteOS2008Detector().Detect(context.Background(), data)
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1: empty OperatingSystem must be ignored, not counted", findings[0].Count)
	}
}

func TestObsoleteOS2008_CaseInsensitiveStillFires(t *testing.T) {
	data := &audit.DetectorData{
		Computers: []types.Computer{
			{DN: "CN=OLDSRV,DC=contoso,DC=com", OperatingSystem: "WINDOWS SERVER 2008 STANDARD"},
		},
	}
	findings := NewObsoleteOS2008Detector().Detect(context.Background(), data)
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1: match must be case-insensitive", findings[0].Count)
	}
}

// TestObsoleteOS2008_R2GluedNoSpaceExcludedNotFlagged covers a known
// limitation of the R2 exclusion: the check only tests whether "r2"
// appears ANYWHERE in the lowercased OS string, not whether it directly
// follows "2008" as a distinct token. A string like "2008R2" (no space
// before R2) still contains "r2" as a substring, so it is excluded here
// exactly like the space-separated form - this is deliberate current
// behavior, not a bug this ticket fixes.
func TestObsoleteOS2008_R2GluedNoSpaceExcludedNotFlagged(t *testing.T) {
	data := &audit.DetectorData{
		Computers: []types.Computer{
			{DN: "CN=SRV2R2GLUED,DC=contoso,DC=com", OperatingSystem: "Windows Server 2008R2 Standard"},
		},
	}
	findings := NewObsoleteOS2008Detector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0: \"2008R2\" (no space) still contains \"r2\" anywhere in the string, so it is excluded like the spaced form", findings[0].Count)
	}
}

func TestObsoleteOS2008_MixedListCountMatchesEntities(t *testing.T) {
	data := &audit.DetectorData{
		IncludeDetails: true,
		Computers: []types.Computer{
			{DN: "CN=SRV1,DC=contoso,DC=com", OperatingSystem: "Windows Server 2008 Standard"},
			{DN: "CN=SRV2,DC=contoso,DC=com", OperatingSystem: "Windows Server 2008 R2 Standard"},
			{DN: "CN=WKS1,DC=contoso,DC=com", OperatingSystem: "Windows 11 Enterprise"},
		},
	}
	findings := NewObsoleteOS2008Detector().Detect(context.Background(), data)
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1 (only SRV1; SRV2 is R2, WKS1 is unrelated)", findings[0].Count)
	}
	if got := findings[0].AffectedEntities[0].DN; got != "CN=SRV1,DC=contoso,DC=com" {
		t.Fatalf("affected DN = %q, want CN=SRV1,DC=contoso,DC=com", got)
	}
}
