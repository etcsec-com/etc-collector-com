package other

import (
	"context"
	"strings"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// TestDCShadow_FlagsDCObjectOutsideStandardOU is a synthetic-data proof that
// DCSHADOW_EVIDENCE actually fires. The detector has never triggered on the
// lab (no plant/revert was ever attempted for a rogue-DC registration), so
// this test builds the two shapes of positive input the code looks for
// (a DomainControllers entry outside OU=Domain Controllers, and a Computer
// carrying the SERVER_TRUST_ACCOUNT UAC flag outside that OU) and confirms
// both are actually flagged, while a properly-placed DC is not.
func TestDCShadow_FlagsDCObjectOutsideStandardOU(t *testing.T) {
	legitDC := types.Computer{
		DN:                 "CN=DC01,OU=Domain Controllers,DC=example,DC=com",
		UserAccountControl: uacServerTrustAccountFlag,
	}
	rogueDC := types.Computer{
		DN:                 "CN=EVIL01,CN=Computers,DC=example,DC=com",
		UserAccountControl: uacServerTrustAccountFlag,
	}

	data := &audit.DetectorData{
		IncludeDetails:    true,
		DomainControllers: []types.Computer{legitDC, rogueDC},
		Computers:         []types.Computer{legitDC, rogueDC},
	}

	findings := NewDCShadowDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	f := findings[0]

	if f.Count != 1 {
		t.Fatalf("expected Count=1 (only the rogue DC outside the standard OU), got %d", f.Count)
	}
	if len(f.AffectedEntities) != 1 || f.AffectedEntities[0].DN != rogueDC.DN {
		t.Fatalf("expected only %q flagged, got %+v", rogueDC.DN, f.AffectedEntities)
	}

	// The description must not overclaim full DCShadow forensic coverage -
	// it should disclose which MITRE-documented evidence classes are NOT
	// checked by this LDAP-snapshot-only heuristic.
	if !strings.Contains(f.Description, "T1207") {
		t.Fatalf("description does not cite MITRE ATT&CK T1207: %q", f.Description)
	}
	descLower := strings.ToLower(f.Description)
	if !strings.Contains(descLower, "does not") {
		t.Fatalf("description does not disclose the detector's partial coverage: %q", f.Description)
	}
}

// TestDCShadow_DoesNotFlagWhenAllDCsInStandardOU covers the negative case:
// no finding should be raised when every DC is correctly placed.
func TestDCShadow_DoesNotFlagWhenAllDCsInStandardOU(t *testing.T) {
	dc := types.Computer{
		DN:                 "CN=DC02,OU=Domain Controllers,DC=example,DC=com",
		UserAccountControl: uacServerTrustAccountFlag,
	}
	data := &audit.DetectorData{
		IncludeDetails:    true,
		DomainControllers: []types.Computer{dc},
		Computers:         []types.Computer{dc},
	}

	findings := NewDCShadowDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 0 {
		t.Fatalf("expected Count=0, got %d (%+v)", findings[0].Count, findings[0].AffectedEntities)
	}
}
