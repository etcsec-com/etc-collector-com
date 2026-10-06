package anssi

import (
	"context"
	"strings"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// --- R15.1 (real controls: R56/R57) ---
//
// The previous implementation flagged an EMPTY "Allowed RODC Password
// Replication Group" as non-compliant when an RODC exists. That's backwards
// per R57's own text: an empty allow list is the safe default. This test
// would have FAILED against the old implementation (empty allow list would
// have produced Count=1 even though both Tier 0 groups sit in the deny
// list) and passes against the fix (deny-list presence is what's checked).
func TestR151RODCNoAllowedRepl_EmptyAllowListButDenyListCorrect_NoFinding(t *testing.T) {
	data := &audit.DetectorData{
		Computers: []types.Computer{{SAMAccountName: "RODC01$", IsRODC: true}},
		Groups: []types.Group{
			{SAMAccountName: "Allowed RODC Password Replication Group", Members: nil},
			{SAMAccountName: "Denied RODC Password Replication Group", Members: []string{
				"CN=Domain Admins,CN=Users,DC=test,DC=local",
				"CN=Enterprise Admins,CN=Users,DC=test,DC=local",
				"CN=Schema Admins,CN=Users,DC=test,DC=local",
			}},
		},
	}
	d := NewR151RODCNoAllowedReplDetector()
	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 0 {
		t.Fatalf("expected no violation (deny list correctly populated despite an empty allow list), got %+v", findings)
	}
}

func TestR151RODCNoAllowedRepl_T0GroupMissingFromDenyList_Flagged(t *testing.T) {
	data := &audit.DetectorData{
		Computers: []types.Computer{{SAMAccountName: "RODC01$", IsRODC: true}},
		Groups: []types.Group{
			{SAMAccountName: "Denied RODC Password Replication Group", Members: []string{
				"CN=Domain Admins,CN=Users,DC=test,DC=local",
				// Enterprise Admins and Schema Admins removed from the deny list.
			}},
		},
	}
	d := NewR151RODCNoAllowedReplDetector()
	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 2 {
		t.Fatalf("expected 2 missing Tier 0 groups flagged, got %+v", findings)
	}
	if strings.Contains(findings[0].Title, "R15.1") || strings.Contains(findings[0].Description, "R15.1") {
		t.Errorf("finding should not cite the nonexistent PA-099 R15.1 sub-reco, got title=%q desc=%q", findings[0].Title, findings[0].Description)
	}
	if !strings.Contains(findings[0].Description, "R57") {
		t.Errorf("description should cite the real source R57, got %q", findings[0].Description)
	}
}

func TestR151RODCNoAllowedRepl_NoRODC_NA(t *testing.T) {
	data := &audit.DetectorData{Computers: []types.Computer{{SAMAccountName: "WKS01$"}}}
	d := NewR151RODCNoAllowedReplDetector()
	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 0 {
		t.Fatalf("expected N/A (no RODC), got %+v", findings)
	}
}
