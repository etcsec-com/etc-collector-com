package gpo

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
)

// TestFolderOptionsNotHardened_UserHiveCountsAsHardened is the RED->GREEN
// case for a cross-detector consequence: DefaultFileTypeRisk/
// LowRiskFileTypes are User Configuration policies and were only ever looked
// up in the Machine hive, so a domain that correctly hardens Attachment
// Manager via User Configuration (the only place Windows actually applies
// it) was reported as having NO hardening GPO at all - a guaranteed false
// positive on every domain that does this correctly.
func TestFolderOptionsNotHardened_UserHiveCountsAsHardened(t *testing.T) {
	risk := 6150 // High risk - properly hardened
	data := &audit.DetectorData{
		GPOPolicies: map[string]*audit.GPOPolicy{
			"{GUID}": {
				UserRegistrySettings: &audit.RegistrySettings{
					FolderOptionsDefaultFileTypeRisk: &risk,
				},
			},
		},
	}

	findings := NewFolderOptionsNotHardenedDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 0 {
		t.Fatalf("a User-hive hardening GPO must count, got count=%d (false positive)", findings[0].Count)
	}
}

// TestFolderOptionsNotHardened_NoGPOFires guards the pre-existing path.
func TestFolderOptionsNotHardened_NoGPOFires(t *testing.T) {
	data := &audit.DetectorData{
		GPOPolicies: map[string]*audit.GPOPolicy{
			"{GUID}": {},
		},
	}

	findings := NewFolderOptionsNotHardenedDetector().Detect(context.Background(), data)
	if findings[0].Count != 1 {
		t.Fatalf("no hardening GPO at all must still fire, got count=%d", findings[0].Count)
	}
}
