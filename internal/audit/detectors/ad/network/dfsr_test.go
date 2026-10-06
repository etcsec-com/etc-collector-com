package network

import (
	"context"
	"strings"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

func detectDfsr(t *testing.T, data *audit.DetectorData) types.Finding {
	t.Helper()
	findings := NewDfsrDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	return findings[0]
}

// TestDfsr_HighFunctionalLevelWithFRSIsFlagged is RED on the pre-fix
// detector: it only checked domainFunctionalLevel <= 2 (Windows Server 2003
// or older) and never looked at DomainInfo.UsingNTFRSForSYSVOL, so a domain
// stuck on FRS at a modern (>= 2008) functional level was never flagged -
// exactly the blind spot this closes.
func TestDfsr_HighFunctionalLevelWithFRSIsFlagged(t *testing.T) {
	f := detectDfsr(t, &audit.DetectorData{
		DomainInfo: &types.DomainInfo{
			FunctionalLevelInt:  7, // Windows Server 2016
			UsingNTFRSForSYSVOL: true,
		},
	})
	if f.Count != 1 {
		t.Fatalf("a domain confirmed on FRS at functional level 7 must be flagged, count=%d", f.Count)
	}
	if !strings.Contains(f.Description, "learn.microsoft.com") {
		t.Errorf("description must cite the Microsoft source, got %q", f.Description)
	}
	if f.Details["microsoftDoc"] == "" {
		t.Error("Details must carry the Microsoft doc URL")
	}
}

// TestDfsr_LowFunctionalLevelNotFlagged: below the level where DFSR became
// available, staying on FRS isn't an actionable finding (nowhere to
// migrate to yet).
func TestDfsr_LowFunctionalLevelNotFlagged(t *testing.T) {
	f := detectDfsr(t, &audit.DetectorData{
		DomainInfo: &types.DomainInfo{
			FunctionalLevelInt:  2, // Windows Server 2003
			UsingNTFRSForSYSVOL: true,
		},
	})
	if f.Count != 0 {
		t.Fatalf("a domain below the DFSR-available functional level must not be flagged, count=%d", f.Count)
	}
}

// TestDfsr_NoFRSEvidenceNotFlagged: this is the other half of the old blind
// guess - a high functional level alone (with no confirmed FRS use) must not
// be flagged either, since the old code never checked real replication
// state at all.
func TestDfsr_NoFRSEvidenceNotFlagged(t *testing.T) {
	f := detectDfsr(t, &audit.DetectorData{
		DomainInfo: &types.DomainInfo{
			FunctionalLevelInt:  7,
			UsingNTFRSForSYSVOL: false,
		},
	})
	if f.Count != 0 {
		t.Fatalf("no confirmed FRS use must not be flagged regardless of functional level, count=%d", f.Count)
	}
}

func TestDfsr_NoDomainInfo(t *testing.T) {
	f := detectDfsr(t, &audit.DetectorData{})
	if f.Count != 0 {
		t.Fatalf("missing domain info must not be flagged, count=%d", f.Count)
	}
}
