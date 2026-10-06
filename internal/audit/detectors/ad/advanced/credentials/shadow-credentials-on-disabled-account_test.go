package credentials

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// TestShadowCredentialsOnDisabledAccount_FiresOnlyOnDisabledUserWithKeyCredential
// isolates the User branch: a disabled user carrying msDS-KeyCredentialLink
// must count, an active user carrying the exact same key credential shape
// must not, and a disabled user with no key credential must not. No Computer
// is present, so this test can only fail if the User-side guard regresses.
func TestShadowCredentialsOnDisabledAccount_FiresOnlyOnDisabledUserWithKeyCredential(t *testing.T) {
	data := &audit.DetectorData{
		IncludeDetails: true,
		Users: []types.User{
			{DN: "CN=disabled-bob,OU=Users,DC=contoso,DC=com", SAMAccountName: "disabled-bob", Disabled: true, KeyCredentialLink: []byte{0x11}},
			{DN: "CN=active-carol,OU=Users,DC=contoso,DC=com", SAMAccountName: "active-carol", KeyCredentialLink: []byte{0x12}},
			{DN: "CN=disabled-clean,OU=Users,DC=contoso,DC=com", SAMAccountName: "disabled-clean", Disabled: true},
		},
	}

	findings := NewShadowCredentialsOnDisabledAccountDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 1 {
		t.Fatalf("expected Count=1 (only disabled-bob), got %d", findings[0].Count)
	}
	if len(findings[0].AffectedEntities) != 1 {
		t.Fatalf("expected 1 affected entity, got %d", len(findings[0].AffectedEntities))
	}
	if got := findings[0].AffectedEntities[0].DN; got != "CN=disabled-bob,OU=Users,DC=contoso,DC=com" {
		t.Fatalf("expected disabled-bob's DN, got %q", got)
	}
}

// TestShadowCredentialsOnDisabledAccount_FiresOnlyOnDisabledComputerWithKeyCredential
// is the Computer-branch mirror, isolated the same way (no User present).
func TestShadowCredentialsOnDisabledAccount_FiresOnlyOnDisabledComputerWithKeyCredential(t *testing.T) {
	data := &audit.DetectorData{
		IncludeDetails: true,
		Computers: []types.Computer{
			{DN: "CN=DISABLEDWKS,OU=Workstations,DC=contoso,DC=com", SAMAccountName: "DISABLEDWKS$", Disabled: true, KeyCredentialLink: []byte{0x15}},
			{DN: "CN=ACTIVEWKS,OU=Workstations,DC=contoso,DC=com", SAMAccountName: "ACTIVEWKS$", KeyCredentialLink: []byte{0x16}},
			{DN: "CN=DISABLEDCLEAN,OU=Workstations,DC=contoso,DC=com", SAMAccountName: "DISABLEDCLEAN$", Disabled: true},
		},
	}

	findings := NewShadowCredentialsOnDisabledAccountDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 1 {
		t.Fatalf("expected Count=1 (only DISABLEDWKS), got %d", findings[0].Count)
	}
	if len(findings[0].AffectedEntities) != 1 {
		t.Fatalf("expected 1 affected entity, got %d", len(findings[0].AffectedEntities))
	}
	if got := findings[0].AffectedEntities[0].DN; got != "CN=DISABLEDWKS,OU=Workstations,DC=contoso,DC=com" {
		t.Fatalf("expected DISABLEDWKS's DN, got %q", got)
	}
}

// TestShadowCredentialsOnDisabledAccount_ExcludesActiveUser isolates the
// guard's User-side mutation kill: only an active user is present (no
// Computer at all), carrying a key credential. If the User Disabled guard
// regresses to accept active users, this is the only test that can catch it
// without the Computer branch masking the failure.
func TestShadowCredentialsOnDisabledAccount_ExcludesActiveUser(t *testing.T) {
	data := &audit.DetectorData{
		IncludeDetails: true,
		Users: []types.User{
			{DN: "CN=active-dave,OU=Users,DC=contoso,DC=com", SAMAccountName: "active-dave", KeyCredentialLink: []byte{0x13}},
		},
	}

	findings := NewShadowCredentialsOnDisabledAccountDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("an active user carrying msDS-KeyCredentialLink must not fire in the disabled-account detector, got count=%d", findings[0].Count)
	}
}

// TestShadowCredentialsOnDisabledAccount_ExcludesActiveComputer is the
// Computer-branch mirror, isolated the same way (no User present).
func TestShadowCredentialsOnDisabledAccount_ExcludesActiveComputer(t *testing.T) {
	data := &audit.DetectorData{
		IncludeDetails: true,
		Computers: []types.Computer{
			{DN: "CN=ACTIVEWKS02,OU=Workstations,DC=contoso,DC=com", SAMAccountName: "ACTIVEWKS02$", KeyCredentialLink: []byte{0x14}},
		},
	}

	findings := NewShadowCredentialsOnDisabledAccountDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("an active computer carrying msDS-KeyCredentialLink must not fire in the disabled-account detector, got count=%d", findings[0].Count)
	}
}

// TestShadowCredentialsOnDisabledAccount_CombinedUserAndComputer guards the
// combined Count/AffectedEntities accounting once both populations are
// checked, mirroring shadow-credentials_test.go's combined test for the
// active detector. Both carriers use a single-byte value so a `> 1`
// mutation of either length guard would silently drop both entries to
// Count=0, not just fail to add them.
func TestShadowCredentialsOnDisabledAccount_CombinedUserAndComputer(t *testing.T) {
	data := &audit.DetectorData{
		IncludeDetails: true,
		Users: []types.User{
			{DN: "CN=disabled-alice,OU=Users,DC=contoso,DC=com", SAMAccountName: "disabled-alice", Disabled: true, KeyCredentialLink: []byte{0x17}},
		},
		Computers: []types.Computer{
			{DN: "CN=DISABLEDWKS02,OU=Workstations,DC=contoso,DC=com", SAMAccountName: "DISABLEDWKS02$", Disabled: true, KeyCredentialLink: []byte{0x18}},
		},
	}

	findings := NewShadowCredentialsOnDisabledAccountDetector().Detect(context.Background(), data)
	if findings[0].Count != 2 {
		t.Fatalf("expected Count=2 (1 disabled user + 1 disabled computer), got %d", findings[0].Count)
	}
	if len(findings[0].AffectedEntities) != 2 {
		t.Fatalf("expected 2 affected entities, got %d", len(findings[0].AffectedEntities))
	}
	// Detect() appends user entities before computer entities, same order as
	// shadow-credentials.go; pin that order literally.
	if got := findings[0].AffectedEntities[0].Type; got != "user" {
		t.Fatalf("expected AffectedEntities[0].Type=user, got %q", got)
	}
	if got := findings[0].AffectedEntities[1].Type; got != "computer" {
		t.Fatalf("expected AffectedEntities[1].Type=computer, got %q", got)
	}
}

// TestShadowCredentialsOnDisabledAccount_EmptyAndNilValuesNotCounted
// exercises both zero forms a caller might set - an explicit empty
// (non-nil) slice, and a nil slice - on disabled carriers of both types.
// len(...) > 0 must reject both regardless of the Disabled guard.
func TestShadowCredentialsOnDisabledAccount_EmptyAndNilValuesNotCounted(t *testing.T) {
	data := &audit.DetectorData{
		IncludeDetails: true,
		Users: []types.User{
			{DN: "CN=disabled-empty-user,OU=Users,DC=contoso,DC=com", SAMAccountName: "disabled-empty-user", Disabled: true, KeyCredentialLink: []byte{}},
			{DN: "CN=disabled-nil-user,OU=Users,DC=contoso,DC=com", SAMAccountName: "disabled-nil-user", Disabled: true, KeyCredentialLink: nil},
		},
		Computers: []types.Computer{
			{DN: "CN=DISABLEDEMPTYWKS,OU=Workstations,DC=contoso,DC=com", SAMAccountName: "DISABLEDEMPTYWKS$", Disabled: true, KeyCredentialLink: []byte{}},
			{DN: "CN=DISABLEDNILWKS,OU=Workstations,DC=contoso,DC=com", SAMAccountName: "DISABLEDNILWKS$", Disabled: true, KeyCredentialLink: nil},
		},
	}

	findings := NewShadowCredentialsOnDisabledAccountDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("expected Count=0 for empty/nil KeyCredentialLink on both types, got %d", findings[0].Count)
	}
	if len(findings[0].AffectedEntities) != 0 {
		t.Fatalf("expected 0 affected entities, got %d", len(findings[0].AffectedEntities))
	}
}

// TestShadowCredentialsOnDisabledAccount_IncludeDetailsFalseOmitsEntities
// guards the data.IncludeDetails gate: Count must still reflect both carrier
// populations, but AffectedEntities must stay empty when the caller did not
// ask for details.
func TestShadowCredentialsOnDisabledAccount_IncludeDetailsFalseOmitsEntities(t *testing.T) {
	data := &audit.DetectorData{
		IncludeDetails: false,
		Users: []types.User{
			{DN: "CN=disabled-frank,OU=Users,DC=contoso,DC=com", SAMAccountName: "disabled-frank", Disabled: true, KeyCredentialLink: []byte{0x19}},
		},
		Computers: []types.Computer{
			{DN: "CN=DISABLEDWKS03,OU=Workstations,DC=contoso,DC=com", SAMAccountName: "DISABLEDWKS03$", Disabled: true, KeyCredentialLink: []byte{0x1A}},
		},
	}

	findings := NewShadowCredentialsOnDisabledAccountDetector().Detect(context.Background(), data)
	if findings[0].Count != 2 {
		t.Fatalf("expected Count=2 (IncludeDetails must not affect counting), got %d", findings[0].Count)
	}
	if len(findings[0].AffectedEntities) != 0 {
		t.Fatalf("expected 0 affected entities with IncludeDetails=false, got %d", len(findings[0].AffectedEntities))
	}
}

// TestShadowCredentialsOnDisabledAccount_TypeAndSeverityLiteral pins the
// finding's static fields against LITERAL strings, not against the
// detector's own constants.
func TestShadowCredentialsOnDisabledAccount_TypeAndSeverityLiteral(t *testing.T) {
	data := &audit.DetectorData{
		Users: []types.User{
			{DN: "CN=disabled-grace,OU=Users,DC=contoso,DC=com", SAMAccountName: "disabled-grace", Disabled: true, KeyCredentialLink: []byte{0x1B}},
		},
	}

	findings := NewShadowCredentialsOnDisabledAccountDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if got := findings[0].Type; got != "SHADOW_CREDENTIALS_ON_DISABLED_ACCOUNT" {
		t.Fatalf("expected Type literal \"SHADOW_CREDENTIALS_ON_DISABLED_ACCOUNT\", got %q", got)
	}
	if got := string(findings[0].Severity); got != "low" {
		t.Fatalf("expected Severity literal \"low\", got %q", got)
	}
	if got := findings[0].Category; got != "advanced" {
		t.Fatalf("expected Category literal \"advanced\", got %q", got)
	}
}

// TestShadowCredentials_PartitionIsExhaustive covers both detectors
// together, for both populations: a user or computer carrying a key
// credential is counted by exactly one of the two - active or disabled -
// never both, never neither.
func TestShadowCredentials_PartitionIsExhaustive(t *testing.T) {
	data := &audit.DetectorData{
		IncludeDetails: true,
		Users: []types.User{
			{DN: "CN=active-match,OU=Users,DC=contoso,DC=com", SAMAccountName: "active-match", KeyCredentialLink: []byte{0x21}},
			{DN: "CN=disabled-match,OU=Users,DC=contoso,DC=com", SAMAccountName: "disabled-match", Disabled: true, KeyCredentialLink: []byte{0x22}},
		},
		Computers: []types.Computer{
			{DN: "CN=ACTIVEWKS03,OU=Workstations,DC=contoso,DC=com", SAMAccountName: "ACTIVEWKS03$", KeyCredentialLink: []byte{0x23}},
			{DN: "CN=DISABLEDWKS04,OU=Workstations,DC=contoso,DC=com", SAMAccountName: "DISABLEDWKS04$", Disabled: true, KeyCredentialLink: []byte{0x24}},
		},
	}

	active := NewShadowCredentialsDetector().Detect(context.Background(), data)
	disabled := NewShadowCredentialsOnDisabledAccountDetector().Detect(context.Background(), data)

	if active[0].Count != 2 {
		t.Fatalf("active half: want 2 (active-match user + ACTIVEWKS03 computer), got %d", active[0].Count)
	}
	if disabled[0].Count != 2 {
		t.Fatalf("disabled half: want 2 (disabled-match user + DISABLEDWKS04 computer), got %d", disabled[0].Count)
	}
}
