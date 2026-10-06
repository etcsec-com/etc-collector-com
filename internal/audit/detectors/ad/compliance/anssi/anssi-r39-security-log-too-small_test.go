package anssi

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
)

// The previous implementation accepted a large SecurityLogMaxSizeKB from
// any GPO regardless of what it's linked to. A GPO setting 1 GB but linked
// only to an unrelated OU never reaches the Domain Controllers whose 20 MB
// default this check exists to catch. This test would have FAILED against
// the old implementation (any GPO with the size setting => compliant) and
// passes against the fix (linkage to DCs is required).
func TestR39SecurityLogSize_LargeSizeLinkedElsewhere_StillFlagged(t *testing.T) {
	sizeKB := 2097152 // 2 GB
	data := &audit.DetectorData{
		GPOPolicies: map[string]*audit.GPOPolicy{
			"{aaaaaaaa-1111-2222-3333-444444444444}": {
				GUID:             "{aaaaaaaa-1111-2222-3333-444444444444}",
				RegistrySettings: &audit.RegistrySettings{SecurityLogMaxSizeKB: &sizeKB},
			},
		},
		GPOLinks: []audit.GPOLink{
			{GPOCN: "aaaaaaaa-1111-2222-3333-444444444444", LinkedTo: "OU=Workstations,DC=test,DC=local", LinkEnabled: true},
		},
	}
	d := NewR39SecurityLogSizeDetector()
	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 1 {
		t.Fatalf("expected a large-size GPO linked away from the DCs to still be flagged, got %+v", findings)
	}
}

func TestR39SecurityLogSize_LargeSizeLinkedToDCsOU_NotFlagged(t *testing.T) {
	sizeKB := 2097152
	data := &audit.DetectorData{
		GPOPolicies: map[string]*audit.GPOPolicy{
			"{aaaaaaaa-1111-2222-3333-444444444444}": {
				GUID:             "{aaaaaaaa-1111-2222-3333-444444444444}",
				RegistrySettings: &audit.RegistrySettings{SecurityLogMaxSizeKB: &sizeKB},
			},
		},
		GPOLinks: []audit.GPOLink{
			{GPOCN: "aaaaaaaa-1111-2222-3333-444444444444", LinkedTo: "OU=Domain Controllers,DC=test,DC=local", LinkEnabled: true},
		},
	}
	d := NewR39SecurityLogSizeDetector()
	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 0 {
		t.Fatalf("expected a large-size GPO linked to the DC OU to be compliant, got %+v", findings)
	}
}
