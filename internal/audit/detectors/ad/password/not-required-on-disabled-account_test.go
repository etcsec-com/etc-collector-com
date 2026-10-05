package password

import (
	"context"
	"strings"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// TestNotRequiredOnDisabledAccount_OnlyDisabledCounted mirrors
// TestNotRequired_DisabledAccountExcluded from the sibling file: the two
// detectors must partition the same population with no overlap and no gap.
// Fixtures are multi-bit and realistic (0x220 = NORMAL_ACCOUNT|PASSWD_NOTREQD,
// 0x222 adds ACCOUNTDISABLE), not the mono-bit 0x20 that a `==` comparison
// could match by coincidence in place of the intended bitwise AND.
func TestNotRequiredOnDisabledAccount_OnlyDisabledCounted(t *testing.T) {
	data := &audit.DetectorData{
		IncludeDetails: true,
		Users: []types.User{
			{SAMAccountName: "active-nopass", UserAccountControl: 0x220, Disabled: false},
			{SAMAccountName: "stale-disabled", UserAccountControl: 0x222, Disabled: true},
		},
	}

	findings := NewNotRequiredOnDisabledAccountDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("len(findings) = %d, want 1", len(findings))
	}
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1 (only the disabled account)", findings[0].Count)
	}
	if findings[0].Severity != types.SeverityLow {
		t.Fatalf("Severity = %s, want low", findings[0].Severity)
	}
	if len(findings[0].AffectedEntities) != 1 || findings[0].AffectedEntities[0].SAMAccountName != "stale-disabled" {
		t.Fatalf("AffectedEntities = %+v, want only stale-disabled", findings[0].AffectedEntities)
	}
}

// TestNotRequiredOnDisabledAccount_EnabledNotFlagged guards the negative case.
func TestNotRequiredOnDisabledAccount_EnabledNotFlagged(t *testing.T) {
	data := &audit.DetectorData{
		Users: []types.User{{SAMAccountName: "active-nopass", UserAccountControl: 0x20, Disabled: false}},
	}

	findings := NewNotRequiredOnDisabledAccountDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0", findings[0].Count)
	}
}

// TestNotRequiredOnDisabledAccount_InterdomainTrustAccountExcluded pins the
// exclusion: a disabled interdomain trust account (UAC 0x822 = PASSWD_NOTREQD
// | ID | DISABLE) is a documented Windows default (KB 305144), not a finding -
// only a plain disabled PASSWD_NOTREQD account in the same population is
// counted. Fixture uses the literal 0x822, never
// types.UACInterdomainTrustAccount, so a wrong constant value could never
// make this test pass by accident.
func TestNotRequiredOnDisabledAccount_InterdomainTrustAccountExcluded(t *testing.T) {
	data := &audit.DetectorData{
		IncludeDetails: true,
		Users: []types.User{
			{SAMAccountName: "legacy-trust", UserAccountControl: 0x822, Disabled: true},
			{SAMAccountName: "stale-disabled", UserAccountControl: 0x22, Disabled: true},
		},
	}

	findings := NewNotRequiredOnDisabledAccountDetector().Detect(context.Background(), data)
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1 (interdomain trust account must be excluded)", findings[0].Count)
	}
	if len(findings[0].AffectedEntities) != 1 || findings[0].AffectedEntities[0].SAMAccountName != "stale-disabled" {
		t.Fatalf("AffectedEntities = %+v, want only stale-disabled", findings[0].AffectedEntities)
	}
}

// TestNotRequiredOnDisabledAccount_DescriptionText pins the text fix: no
// promise of credential-less authentication, and the interdomain trust
// exclusion named.
func TestNotRequiredOnDisabledAccount_DescriptionText(t *testing.T) {
	findings := NewNotRequiredOnDisabledAccountDetector().Detect(context.Background(), &audit.DetectorData{})
	desc := findings[0].Description

	if strings.Contains(desc, "without credentials") {
		t.Fatalf("Description still promises credential-less authentication: %q", desc)
	}
	if !strings.Contains(desc, "0x800") {
		t.Fatalf("Description does not name the interdomain trust account exclusion: %q", desc)
	}
	if !strings.Contains(desc, "MS-ADTS 2.2.16") {
		t.Fatalf("Description does not cite MS-ADTS 2.2.16: %q", desc)
	}
}

// TestNotRequiredOnDisabledAccount_DescriptionMatchesDoc couples the runtime
// finding text to the catalog Doc(): the substring checks above cannot catch
// a drift between the two (e.g. a typo'd KB number) as long as the named
// substrings survive.
func TestNotRequiredOnDisabledAccount_DescriptionMatchesDoc(t *testing.T) {
	d := NewNotRequiredOnDisabledAccountDetector()
	findings := d.Detect(context.Background(), &audit.DetectorData{})
	doc := d.Doc()

	if findings[0].Description != doc.Description {
		t.Fatalf("Detect() Description drifted from Doc():\nDetect: %q\nDoc:    %q", findings[0].Description, doc.Description)
	}
	if findings[0].Title != doc.Title {
		t.Fatalf("Detect() Title drifted from Doc(): Detect=%q Doc=%q", findings[0].Title, doc.Title)
	}
}
