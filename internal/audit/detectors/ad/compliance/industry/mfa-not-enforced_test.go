package industry

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// UAC literals used by the test cases below. Written out rather than
// reusing the detector's own uacSmartcardRequired constant, so a drift in
// that constant's value cannot silently make these tests pass for the
// wrong reason.
const (
	uacNormal              = 0x200   // 512
	uacNormalPlusSmartcard = 0x40200 // 262656 - NORMAL + SMARTCARD_REQUIRED
)

// TestMFANotEnforced_AdminWithoutSmartcard_Fires mirrors the t492adminnosmart
// plant: an enabled Domain Admins member with no SMARTCARD_REQUIRED bit must
// be counted both in totalAdmins and in the finding.
func TestMFANotEnforced_AdminWithoutSmartcard_Fires(t *testing.T) {
	domainAdminsDN := "CN=Domain Admins,CN=Users,DC=lab,DC=local"
	data := &audit.DetectorData{
		IncludeDetails: true,
		Groups: []types.Group{
			{DN: domainAdminsDN, SAMAccountName: "Domain Admins", ObjectSID: "S-1-5-21-1-2-3-512"},
		},
		Users: []types.User{
			{
				DN:                 "CN=t492adminnosmart,DC=lab,DC=local",
				SAMAccountName:     "t492adminnosmart",
				MemberOf:           []string{domainAdminsDN},
				UserAccountControl: uacNormal,
			},
		},
	}
	findings := NewMFANotEnforcedDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if totalAdmins, _ := findings[0].Details["totalAdmins"].(int); totalAdmins != 1 {
		t.Errorf("totalAdmins = %v, want 1", totalAdmins)
	}
	if findings[0].Count != 1 {
		t.Errorf("Count = %d, want 1 (admin without SMARTCARD_REQUIRED must fire)", findings[0].Count)
	}
}

// TestMFANotEnforced_AdminWithSmartcard_DoesNotFire mirrors the
// t492adminsmart plant: an enabled Domain Admins member with the
// SMARTCARD_REQUIRED bit set is still a privileged admin (counted in
// totalAdmins) but must NOT appear in the finding.
//
// This test kills the "bit retire" mutation: if the SMARTCARD_REQUIRED mask
// check in Detect is removed or short-circuited to always treat admins as
// unprotected, this account would incorrectly inflate Count from 0 to 1.
func TestMFANotEnforced_AdminWithSmartcard_DoesNotFire(t *testing.T) {
	domainAdminsDN := "CN=Domain Admins,CN=Users,DC=lab,DC=local"
	data := &audit.DetectorData{
		IncludeDetails: true,
		Groups: []types.Group{
			{DN: domainAdminsDN, SAMAccountName: "Domain Admins", ObjectSID: "S-1-5-21-1-2-3-512"},
		},
		Users: []types.User{
			{
				DN:                 "CN=t492adminsmart,DC=lab,DC=local",
				SAMAccountName:     "t492adminsmart",
				MemberOf:           []string{domainAdminsDN},
				UserAccountControl: uacNormalPlusSmartcard,
			},
		},
	}
	findings := NewMFANotEnforcedDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if totalAdmins, _ := findings[0].Details["totalAdmins"].(int); totalAdmins != 1 {
		t.Errorf("totalAdmins = %v, want 1 (still a privileged admin, just MFA-enforced)", totalAdmins)
	}
	if findings[0].Count != 0 {
		t.Errorf("Count = %d, want 0 (SMARTCARD_REQUIRED admin must not fire)", findings[0].Count)
	}
}

// TestMFANotEnforced_NonPrivilegedWithoutSmartcard_DoesNotFire mirrors the
// t492nonpriv plant: an enabled, non-admin user with no SMARTCARD_REQUIRED
// bit must not be counted anywhere - this detector only cares about
// privileged accounts.
func TestMFANotEnforced_NonPrivilegedWithoutSmartcard_DoesNotFire(t *testing.T) {
	data := &audit.DetectorData{
		IncludeDetails: true,
		Users: []types.User{
			{
				DN:                 "CN=t492nonpriv,DC=lab,DC=local",
				SAMAccountName:     "t492nonpriv",
				UserAccountControl: uacNormal,
			},
		},
	}
	findings := NewMFANotEnforcedDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if totalAdmins, _ := findings[0].Details["totalAdmins"].(int); totalAdmins != 0 {
		t.Errorf("totalAdmins = %v, want 0 (not a privileged account)", totalAdmins)
	}
	if findings[0].Count != 0 {
		t.Errorf("Count = %d, want 0 (non-privileged account must not fire)", findings[0].Count)
	}
}

// TestMFANotEnforced_DisabledAdminWithoutSmartcard_Excluded kills the
// "garde Enabled retiree" mutation: if the `if !u.Enabled() continue` guard
// at the top of the loop is removed, this disabled Domain Admins member
// without SMARTCARD_REQUIRED would be processed and counted anyway.
func TestMFANotEnforced_DisabledAdminWithoutSmartcard_Excluded(t *testing.T) {
	domainAdminsDN := "CN=Domain Admins,CN=Users,DC=lab,DC=local"
	data := &audit.DetectorData{
		IncludeDetails: true,
		Groups: []types.Group{
			{DN: domainAdminsDN, SAMAccountName: "Domain Admins", ObjectSID: "S-1-5-21-1-2-3-512"},
		},
		Users: []types.User{
			{
				DN:                 "CN=disabled-admin,DC=lab,DC=local",
				SAMAccountName:     "disabledadmin",
				MemberOf:           []string{domainAdminsDN},
				UserAccountControl: uacNormal,
				Disabled:           true,
			},
		},
	}
	findings := NewMFANotEnforcedDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if totalAdmins, _ := findings[0].Details["totalAdmins"].(int); totalAdmins != 0 {
		t.Errorf("totalAdmins = %v, want 0 (disabled account must be excluded before admin check)", totalAdmins)
	}
	if findings[0].Count != 0 {
		t.Errorf("Count = %d, want 0 (disabled admin must not fire)", findings[0].Count)
	}
}

// TestMFANotEnforced_SchemaAdminsViaMemberOf_RIDSuffixMatch kills the
// "RID vide" mutation: if privilegedRIDs is emptied, no memberOf-based SID
// suffix can ever match, so a Schema Admins (-518) member reached only
// through memberOf (not PrimaryGroupID) would silently stop being counted.
func TestMFANotEnforced_SchemaAdminsViaMemberOf_RIDSuffixMatch(t *testing.T) {
	schemaAdminsDN := "CN=Schema Admins,CN=Users,DC=lab,DC=local"
	data := &audit.DetectorData{
		IncludeDetails: true,
		Groups: []types.Group{
			{DN: schemaAdminsDN, SAMAccountName: "Schema Admins", ObjectSID: "S-1-5-21-1-2-3-518"},
		},
		Users: []types.User{
			{
				DN:                 "CN=schema-admin,DC=lab,DC=local",
				SAMAccountName:     "schemaadmin",
				MemberOf:           []string{schemaAdminsDN},
				UserAccountControl: uacNormal,
			},
		},
	}
	findings := NewMFANotEnforcedDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if totalAdmins, _ := findings[0].Details["totalAdmins"].(int); totalAdmins != 1 {
		t.Errorf("totalAdmins = %v, want 1 (Schema Admins member via memberOf, RID suffix -518)", totalAdmins)
	}
	if findings[0].Count != 1 {
		t.Errorf("Count = %d, want 1", findings[0].Count)
	}
}

// TestMFANotEnforced_FrenchGroupNames covers a regression where the previous
// implementation matched memberOf against the English strings "domain
// admins"/"enterprise admins"/"schema admins". On a French-installed AD -
// where these built-in groups are named "Admins du domaine",
// "Administrateurs de l'entreprise", "Administrateurs du schéma" - every
// privileged user's memberOf failed that match, so totalAdmins stayed 0 and
// the detector went silent regardless of MFA enforcement. This test would
// have FAILED against the old implementation (totalAdmins=0, no finding) and
// passes against the RID-based fix (locale-independent).
func TestMFANotEnforced_FrenchGroupNames(t *testing.T) {
	domainAdminsDN := "CN=Admins du domaine,CN=Users,DC=lab,DC=local"
	data := &audit.DetectorData{
		IncludeDetails: true,
		Groups: []types.Group{
			{DN: domainAdminsDN, SAMAccountName: "Admins du domaine", ObjectSID: "S-1-5-21-1-2-3-512"},
		},
		Users: []types.User{
			{
				DN:                 "CN=Jean Dupont,DC=lab,DC=local",
				SAMAccountName:     "jdupont",
				MemberOf:           []string{domainAdminsDN},
				UserAccountControl: 0, // no smartcard-required flag
			},
		},
	}
	findings := NewMFANotEnforcedDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	totalAdmins, _ := findings[0].Details["totalAdmins"].(int)
	if totalAdmins != 1 {
		t.Fatalf("totalAdmins = %d, want 1 - French-named Domain Admins group member was not recognized as privileged", totalAdmins)
	}
	if findings[0].Count != 1 {
		t.Errorf("Count = %d, want 1 (the French-domain admin without smartcard)", findings[0].Count)
	}
}

// TestMFANotEnforced_PrimaryGroupIDMembership covers the second half of
// the same finding: AD does not add a memberOf backlink for a user's PRIMARY
// group. A user whose primaryGroupID has been changed to 512 (Domain Admins)
// is a full domain admin without ever appearing in memberOf - a memberOf-only
// scan (English or French) misses them entirely. This test would have FAILED
// against a memberOf-only implementation and passes now that PrimaryGroupID
// is also checked.
func TestMFANotEnforced_PrimaryGroupIDMembership(t *testing.T) {
	data := &audit.DetectorData{
		IncludeDetails: true,
		Users: []types.User{
			{
				DN:                 "CN=Stealth Admin,DC=lab,DC=local",
				SAMAccountName:     "stealthadmin",
				PrimaryGroupID:     512, // Domain Admins, via primary group - no memberOf entry
				UserAccountControl: 0,
			},
		},
	}
	findings := NewMFANotEnforcedDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	totalAdmins, _ := findings[0].Details["totalAdmins"].(int)
	if totalAdmins != 1 {
		t.Fatalf("totalAdmins = %d, want 1 - primary-group Domain Admins membership was not detected", totalAdmins)
	}
}
