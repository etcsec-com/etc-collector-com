package credentials

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// TestShadowCredentials_FiresOnComputerKeyCredentialLink pins the
// computer-account coverage gap: the detector used to check only
// types.User for msDS-KeyCredentialLink, so a computer account carrying a
// shadow-credential key credential (the RBCD/S4U2Self-adjacent vector
// Elad Shamir's original Shadow Credentials research treats as the more
// consequential real-world target) was never reported. This must fail
// against the old user-only code and pass once Computer is also checked.
func TestShadowCredentials_FiresOnComputerKeyCredentialLink(t *testing.T) {
	data := &audit.DetectorData{
		IncludeDetails: true,
		Computers: []types.Computer{
			{
				DN:                "CN=WKS01,OU=Workstations,DC=contoso,DC=com",
				SAMAccountName:    "WKS01$",
				KeyCredentialLink: []byte{0x01, 0x02, 0x03},
			},
			{
				DN:             "CN=WKS02,OU=Workstations,DC=contoso,DC=com",
				SAMAccountName: "WKS02$",
				// No key credential link - must not count.
			},
		},
	}

	findings := NewShadowCredentialsDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 1 {
		t.Fatalf("expected Count=1 for the computer carrying msDS-KeyCredentialLink, got %d", findings[0].Count)
	}
	if len(findings[0].AffectedEntities) != 1 {
		t.Fatalf("expected 1 affected entity, got %d", len(findings[0].AffectedEntities))
	}
	if got := findings[0].AffectedEntities[0].Type; got != "computer" {
		t.Fatalf("expected affected entity Type=computer, got %q", got)
	}
	if got := findings[0].AffectedEntities[0].DN; got != "CN=WKS01,OU=Workstations,DC=contoso,DC=com" {
		t.Fatalf("expected the carrying computer's DN, got %q", got)
	}
}

// TestShadowCredentials_FiresOnUserKeyCredentialLink is the user-side
// mirror of the computer test above: a single carrying user, one
// non-carrying user, literal Count/entity assertions.
func TestShadowCredentials_FiresOnUserKeyCredentialLink(t *testing.T) {
	data := &audit.DetectorData{
		IncludeDetails: true,
		Users: []types.User{
			{
				DN:                "CN=bob,OU=Users,DC=contoso,DC=com",
				SAMAccountName:    "bob",
				KeyCredentialLink: []byte{0x04, 0x05, 0x06},
			},
			{
				DN:             "CN=carol,OU=Users,DC=contoso,DC=com",
				SAMAccountName: "carol",
				// No key credential link - must not count.
			},
		},
	}

	findings := NewShadowCredentialsDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 1 {
		t.Fatalf("expected Count=1 for the user carrying msDS-KeyCredentialLink, got %d", findings[0].Count)
	}
	if len(findings[0].AffectedEntities) != 1 {
		t.Fatalf("expected 1 affected entity, got %d", len(findings[0].AffectedEntities))
	}
	if got := findings[0].AffectedEntities[0].Type; got != "user" {
		t.Fatalf("expected affected entity Type=user, got %q", got)
	}
	if got := findings[0].AffectedEntities[0].DN; got != "CN=bob,OU=Users,DC=contoso,DC=com" {
		t.Fatalf("expected the carrying user's DN, got %q", got)
	}
}

// TestShadowCredentials_FiresOnUserAndComputerCombined guards the combined
// Count/AffectedEntities accounting once both populations are checked. Both
// carriers use a single-byte value (len==1) so that a `> 1` mutation of the
// length guard on either branch is caught: a `> 0` -> `> 1` regression would
// silently drop both entries to Count=0 here, not just fail to add them.
func TestShadowCredentials_FiresOnUserAndComputerCombined(t *testing.T) {
	data := &audit.DetectorData{
		IncludeDetails: true,
		Users: []types.User{
			{DN: "CN=alice,OU=Users,DC=contoso,DC=com", SAMAccountName: "alice", KeyCredentialLink: []byte{0xAA}},
		},
		Computers: []types.Computer{
			{DN: "CN=WKS01,OU=Workstations,DC=contoso,DC=com", SAMAccountName: "WKS01$", KeyCredentialLink: []byte{0xBB}},
		},
	}

	findings := NewShadowCredentialsDetector().Detect(context.Background(), data)
	if findings[0].Count != 2 {
		t.Fatalf("expected Count=2 (1 user + 1 computer), got %d", findings[0].Count)
	}
	if len(findings[0].AffectedEntities) != 2 {
		t.Fatalf("expected 2 affected entities, got %d", len(findings[0].AffectedEntities))
	}
	// Detect() appends user entities before computer entities (shadow-credentials.go:67-68);
	// pin that order literally rather than searching, so a Count-only assertion
	// can't hide the two populations landing in the wrong slice.
	if got := findings[0].AffectedEntities[0].Type; got != "user" {
		t.Fatalf("expected AffectedEntities[0].Type=user, got %q", got)
	}
	if got := findings[0].AffectedEntities[1].Type; got != "computer" {
		t.Fatalf("expected AffectedEntities[1].Type=computer, got %q", got)
	}
}

// TestShadowCredentials_NoKeyCredentialsDoesNotFire is the baseline: no
// user or computer carries msDS-KeyCredentialLink.
func TestShadowCredentials_NoKeyCredentialsDoesNotFire(t *testing.T) {
	data := &audit.DetectorData{
		Users:     []types.User{{DN: "CN=alice,OU=Users,DC=contoso,DC=com", SAMAccountName: "alice"}},
		Computers: []types.Computer{{DN: "CN=WKS01,OU=Workstations,DC=contoso,DC=com", SAMAccountName: "WKS01$"}},
	}

	findings := NewShadowCredentialsDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("expected Count=0, got %d", findings[0].Count)
	}
}

// TestShadowCredentials_EmptyAndNilValuesNotCounted exercises both zero
// forms a caller might set: an explicit empty (non-nil) slice, and a nil
// slice (the zero value, matching what an object that never had the
// attribute collected would carry). len(...) > 0 must reject both.
func TestShadowCredentials_EmptyAndNilValuesNotCounted(t *testing.T) {
	data := &audit.DetectorData{
		IncludeDetails: true,
		Users: []types.User{
			{DN: "CN=empty-user,OU=Users,DC=contoso,DC=com", SAMAccountName: "empty-user", KeyCredentialLink: []byte{}},
			{DN: "CN=nil-user,OU=Users,DC=contoso,DC=com", SAMAccountName: "nil-user", KeyCredentialLink: nil},
		},
		Computers: []types.Computer{
			{DN: "CN=EMPTYWKS,OU=Workstations,DC=contoso,DC=com", SAMAccountName: "EMPTYWKS$", KeyCredentialLink: []byte{}},
			{DN: "CN=NILWKS,OU=Workstations,DC=contoso,DC=com", SAMAccountName: "NILWKS$", KeyCredentialLink: nil},
		},
	}

	findings := NewShadowCredentialsDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("expected Count=0 for empty/nil KeyCredentialLink on both types, got %d", findings[0].Count)
	}
	if len(findings[0].AffectedEntities) != 0 {
		t.Fatalf("expected 0 affected entities, got %d", len(findings[0].AffectedEntities))
	}
}

// TestShadowCredentials_ExcludesDisabledUser isolates the User branch: a
// disabled user carrying msDS-KeyCredentialLink must not fire in the active
// detector anymore - it is reported instead, at Low, by
// ShadowCredentialsOnDisabledAccountDetector. No Computer is present, so
// this test can only fail if the User-side guard regresses.
func TestShadowCredentials_ExcludesDisabledUser(t *testing.T) {
	data := &audit.DetectorData{
		IncludeDetails: true,
		Users: []types.User{
			{
				DN:                "CN=disabled-user,OU=Users,DC=contoso,DC=com",
				SAMAccountName:    "disabled-user",
				Disabled:          true,
				KeyCredentialLink: []byte{0x07},
			},
		},
	}

	findings := NewShadowCredentialsDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("a disabled user carrying msDS-KeyCredentialLink must not fire in the active detector, got count=%d", findings[0].Count)
	}
	if len(findings[0].AffectedEntities) != 0 {
		t.Fatalf("expected 0 affected entities, got %d", len(findings[0].AffectedEntities))
	}
}

// TestShadowCredentials_ExcludesDisabledComputer is the Computer-branch
// mirror, isolated the same way (no User present) so a regression of only
// the Computer-side guard cannot hide behind the User test passing.
func TestShadowCredentials_ExcludesDisabledComputer(t *testing.T) {
	data := &audit.DetectorData{
		IncludeDetails: true,
		Computers: []types.Computer{
			{
				DN:                "CN=DISABLEDWKS,OU=Workstations,DC=contoso,DC=com",
				SAMAccountName:    "DISABLEDWKS$",
				Disabled:          true,
				KeyCredentialLink: []byte{0x08},
			},
		},
	}

	findings := NewShadowCredentialsDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("a disabled computer carrying msDS-KeyCredentialLink must not fire in the active detector, got count=%d", findings[0].Count)
	}
	if len(findings[0].AffectedEntities) != 0 {
		t.Fatalf("expected 0 affected entities, got %d", len(findings[0].AffectedEntities))
	}
}

// TestShadowCredentials_IncludeDetailsFalseOmitsEntities guards the
// data.IncludeDetails gate (shadow-credentials.go:65): Count must still
// reflect both carrier populations, but AffectedEntities must stay empty
// when the caller did not ask for details - regardless of how many
// carriers of either type exist.
func TestShadowCredentials_IncludeDetailsFalseOmitsEntities(t *testing.T) {
	data := &audit.DetectorData{
		IncludeDetails: false,
		Users: []types.User{
			{DN: "CN=dave,OU=Users,DC=contoso,DC=com", SAMAccountName: "dave", KeyCredentialLink: []byte{0x09}},
		},
		Computers: []types.Computer{
			{DN: "CN=WKS03,OU=Workstations,DC=contoso,DC=com", SAMAccountName: "WKS03$", KeyCredentialLink: []byte{0x0A}},
		},
	}

	findings := NewShadowCredentialsDetector().Detect(context.Background(), data)
	if findings[0].Count != 2 {
		t.Fatalf("expected Count=2 (IncludeDetails must not affect counting), got %d", findings[0].Count)
	}
	if len(findings[0].AffectedEntities) != 0 {
		t.Fatalf("expected 0 affected entities with IncludeDetails=false, got %d", len(findings[0].AffectedEntities))
	}
}

// TestShadowCredentials_TypeAndSeverityLiteral pins the finding's static
// fields against LITERAL strings, not against the detector's own
// constants - comparing types.SeverityCritical to itself would make a
// severity regression structurally undetectable, the same trap that let
// the LAPS GUID constant drift silently for months.
func TestShadowCredentials_TypeAndSeverityLiteral(t *testing.T) {
	data := &audit.DetectorData{
		Users: []types.User{
			{DN: "CN=eve,OU=Users,DC=contoso,DC=com", SAMAccountName: "eve", KeyCredentialLink: []byte{0x0B}},
		},
	}

	findings := NewShadowCredentialsDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if got := findings[0].Type; got != "SHADOW_CREDENTIALS" {
		t.Fatalf("expected Type literal \"SHADOW_CREDENTIALS\", got %q", got)
	}
	if got := string(findings[0].Severity); got != "critical" {
		t.Fatalf("expected Severity literal \"critical\", got %q", got)
	}
	if got := findings[0].Category; got != "advanced" {
		t.Fatalf("expected Category literal \"advanced\", got %q", got)
	}
}
