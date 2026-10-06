package network

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

func detectDcBackup(t *testing.T, data *audit.DetectorData) types.Finding {
	t.Helper()
	findings := NewDcBackupDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	return findings[0]
}

// TestDcBackup_DescriptionDoesNotClaimARealBackupDate is RED on the pre-fix
// detector: its description ("Active Directory should be backed up
// regularly. Tombstone lifetime is 180 days.") and its Details key
// ("lastBackup") both presented an NTDS-metadata whenChanged heuristic as if
// it were an actual backup timestamp - the code comment in the LDAP
// collector already admits it's a heuristic, but the detector's output
// never said so.
func TestDcBackup_DescriptionDoesNotClaimARealBackupDate(t *testing.T) {
	now := time.Now()
	old := now.AddDate(0, 0, -90)
	f := detectDcBackup(t, &audit.DetectorData{
		Now: now,
		DomainInfo: &types.DomainInfo{
			LastADBackupDate: &old,
		},
	})

	lower := strings.ToLower(f.Description)
	if !strings.Contains(lower, "indirect") && !strings.Contains(lower, "heuristic") {
		t.Errorf("description must disclose this is an indirect/heuristic indicator, got %q", f.Description)
	}
	if _, ok := f.Details["lastBackup"]; ok {
		t.Error("Details must not use the misleading key \"lastBackup\" for a non-backup timestamp")
	}
	if _, ok := f.Details["lastNtdsMetadataChange"]; !ok {
		t.Error("Details must expose the metadata timestamp under an honestly named key")
	}
}

func TestDcBackup_RecentActivityDoesNotFire(t *testing.T) {
	now := time.Now()
	recent := now.AddDate(0, 0, -10)
	f := detectDcBackup(t, &audit.DetectorData{
		Now: now,
		DomainInfo: &types.DomainInfo{
			LastADBackupDate: &recent,
		},
	})
	if f.Count != 0 {
		t.Fatalf("recent NTDS metadata activity must not fire, count=%d", f.Count)
	}
}

func TestDcBackup_NoDataFires(t *testing.T) {
	f := detectDcBackup(t, &audit.DetectorData{DomainInfo: nil})
	if f.Count != 1 {
		t.Fatalf("missing data must fire so operators verify backups directly, count=%d", f.Count)
	}
}
