package gpo

import (
	"context"
	"strings"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// Without SYSVOL access, the fallback only catches a GPO whose LDAP object
// itself is missing gPCFileSysPath/displayName - it cannot detect a real
// AD/SYSVOL mismatch (an intact AD object pointing at a missing SYSVOL
// folder, or vice versa). The old Description claimed "mismatched AD
// objects and SYSVOL directories" even in fallback mode, which overstates
// what was actually measured. This test fails against that unqualified
// claim and passes once the fallback path's Description discloses its
// narrower scope.
func TestOrphaned_FallbackDescriptionDisclosesNarrowerScope(t *testing.T) {
	data := &audit.DetectorData{
		GPOs: []types.GPO{
			{CN: "{GUID}", DisplayName: "Broken GPO", FilePath: ""},
		},
	}

	findings := NewOrphanedDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1 (GPO missing FilePath)", findings[0].Count)
	}
	if strings.Contains(findings[0].Description, "SYSVOL was not scanned") == false {
		t.Fatalf("fallback description should disclose SYSVOL was not scanned, got %q", findings[0].Description)
	}
}

// With real SYSVOLFindings data, the original (accurate) Description is
// preserved unchanged - confirms the fallback-only rewording doesn't leak
// into the SYSVOL-backed path.
func TestOrphaned_SYSVOLPathKeepsOriginalDescription(t *testing.T) {
	data := &audit.DetectorData{
		SYSVOLFindings: []audit.SYSVOLFinding{
			{Type: "orphaned_ldap", GPOName: "Broken GPO", Details: "no SYSVOL folder"},
		},
	}

	findings := NewOrphanedDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1", findings[0].Count)
	}
	if !strings.Contains(findings[0].Description, "mismatched AD objects and SYSVOL directories") {
		t.Fatalf("SYSVOL-backed path should keep the original description, got %q", findings[0].Description)
	}
}
