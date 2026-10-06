package password

import (
	"context"
	"strings"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// TestNotRequired_DisabledAccountExcluded pins the fix: a disabled account
// carrying PASSWD_NOTREQD (0x20) cannot authenticate today, so it must not
// inflate the Critical population - it is reported separately by
// NotRequiredOnDisabledAccountDetector instead. Fixtures are multi-bit and
// realistic (0x220 = NORMAL_ACCOUNT|PASSWD_NOTREQD, 0x222 adds
// ACCOUNTDISABLE), not the mono-bit 0x20 that a `==` comparison could match
// by coincidence in place of the intended bitwise AND.
func TestNotRequired_DisabledAccountExcluded(t *testing.T) {
	data := &audit.DetectorData{
		IncludeDetails: true,
		Users: []types.User{
			{SAMAccountName: "active-nopass", UserAccountControl: 0x220, Disabled: false},
			{SAMAccountName: "stale-disabled", UserAccountControl: 0x222, Disabled: true},
		},
	}

	findings := NewNotRequiredDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("len(findings) = %d, want 1", len(findings))
	}
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1 (disabled account must be excluded)", findings[0].Count)
	}
	if findings[0].Severity != types.SeverityCritical {
		t.Fatalf("Severity = %s, want critical", findings[0].Severity)
	}
	if len(findings[0].AffectedEntities) != 1 || findings[0].AffectedEntities[0].SAMAccountName != "active-nopass" {
		t.Fatalf("AffectedEntities = %+v, want only active-nopass", findings[0].AffectedEntities)
	}
}

// TestNotRequired_FlagNotSetNotFlagged guards the negative case.
func TestNotRequired_FlagNotSetNotFlagged(t *testing.T) {
	data := &audit.DetectorData{
		Users: []types.User{{SAMAccountName: "ordinary", UserAccountControl: 0x0200}}, // NORMAL_ACCOUNT
	}

	findings := NewNotRequiredDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0", findings[0].Count)
	}
}

// TestNotRequired_InterdomainTrustAccountExcluded pins the exclusion: an
// active interdomain trust account (UAC 0x820 = PASSWD_NOTREQD | ID) is a
// documented Windows default (KB 305144), not a finding - only a plain
// PASSWD_NOTREQD account in the same population is counted. The fixture uses
// the literal 0x820, never types.UACInterdomainTrustAccount, so a wrong
// constant value could never make this test pass by accident.
//
// The third fixture (0x120 = PASSWD_NOTREQD | NORMAL_ACCOUNT, no 0x800 bit)
// distinguishes the real constant (0x800) from a corrupted 0x900: 0x120 & 0x800
// = 0, so it must be counted, but 0x120 & 0x900 = 0x100 != 0, so a drifted
// constant would wrongly exclude it.
func TestNotRequired_InterdomainTrustAccountExcluded(t *testing.T) {
	data := &audit.DetectorData{
		IncludeDetails: true,
		Users: []types.User{
			{SAMAccountName: "legacy-trust", UserAccountControl: 0x820, Disabled: false},
			{SAMAccountName: "active-nopass", UserAccountControl: 0x20, Disabled: false},
			{SAMAccountName: "distinguishes-0x800-from-0x900", UserAccountControl: 0x120, Disabled: false},
		},
	}

	findings := NewNotRequiredDetector().Detect(context.Background(), data)
	if findings[0].Count != 2 {
		t.Fatalf("Count = %d, want 2 (interdomain trust account must be excluded)", findings[0].Count)
	}
	names := []string{findings[0].AffectedEntities[0].SAMAccountName, findings[0].AffectedEntities[1].SAMAccountName}
	if len(findings[0].AffectedEntities) != 2 || names[0] != "active-nopass" || names[1] != "distinguishes-0x800-from-0x900" {
		t.Fatalf("AffectedEntities = %+v, want active-nopass and distinguishes-0x800-from-0x900", findings[0].AffectedEntities)
	}
}

// TestNotRequired_DescriptionText pins the text fix: no promise of
// credential-less authentication, and the interdomain trust exclusion named.
func TestNotRequired_DescriptionText(t *testing.T) {
	findings := NewNotRequiredDetector().Detect(context.Background(), &audit.DetectorData{})
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

// TestNotRequired_DescriptionMatchesDoc couples the runtime finding text to
// the catalog Doc(): the substring checks above cannot catch a drift between
// the two (e.g. a typo'd KB number) as long as the named substrings survive.
func TestNotRequired_DescriptionMatchesDoc(t *testing.T) {
	d := NewNotRequiredDetector()
	findings := d.Detect(context.Background(), &audit.DetectorData{})
	doc := d.Doc()

	if findings[0].Description != doc.Description {
		t.Fatalf("Detect() Description drifted from Doc():\nDetect: %q\nDoc:    %q", findings[0].Description, doc.Description)
	}
	if findings[0].Title != doc.Title {
		t.Fatalf("Detect() Title drifted from Doc(): Detect=%q Doc=%q", findings[0].Title, doc.Title)
	}
}
