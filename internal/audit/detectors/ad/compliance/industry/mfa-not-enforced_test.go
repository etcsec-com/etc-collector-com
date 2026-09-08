package industry

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

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
