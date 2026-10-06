package anssi

import (
	"context"
	"strings"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// TestR3StrongAuth_DoesNotClaimANSSIR3 covers the fact that a full-text audit of
// ANSSI PA-099 found no R-number mandating strong/smartcard authentication -
// the guide explicitly defers the subject to a separate ANSSI publication.
// This test would have FAILED against the old title/description ("ANSSI R3
// - Strong Authentication Non-Compliant", Details["framework"]="ANSSI",
// Details["control"]="R3") and passes now that the fabricated attribution
// is removed.
func TestR3StrongAuth_DoesNotClaimANSSIR3(t *testing.T) {
	adminCount := true
	data := &audit.DetectorData{
		IncludeDetails: true,
		Users: []types.User{
			{DN: "CN=Admin,DC=lab,DC=local", SAMAccountName: "admin", AdminCount: adminCount, UserAccountControl: 0x0200},
		},
	}
	findings := NewR3StrongAuthDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	title, desc := findings[0].Title, findings[0].Description
	if strings.Contains(title, "ANSSI R3") || strings.Contains(desc, "ANSSI R3 ") {
		t.Errorf("finding must not attribute this control to ANSSI R3, got title=%q desc=%q", title, desc)
	}
	if fw, ok := findings[0].Details["framework"]; ok {
		t.Errorf("finding Details should no longer hardcode a fabricated framework/control attribution, got framework=%v control=%v", fw, findings[0].Details["control"])
	}
}

// TestR3StrongAuth_FIDO2KeyCounts covers a regression where the previous implementation
// only recognized the smartcard-required UAC bit, so an admin protected by
// Windows Hello for Business or a FIDO2 key (msDS-KeyCredentialLink) was
// flagged as having no strong authentication at all. This test would have
// FAILED against the old implementation (flagged despite a registered key
// credential) and passes now that KeyCredentialLink is also accepted.
func TestR3StrongAuth_FIDO2KeyCounts(t *testing.T) {
	data := &audit.DetectorData{
		IncludeDetails: true,
		Users: []types.User{
			{
				DN:                 "CN=FIDO2 Admin,DC=lab,DC=local",
				SAMAccountName:     "fido2admin",
				AdminCount:         true,
				UserAccountControl: 0x0200, // no smartcard-required bit
				KeyCredentialLink:  []byte{0x01, 0x02, 0x03},
			},
		},
	}
	findings := NewR3StrongAuthDetector().Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 0 {
		t.Fatalf("expected an admin with a registered FIDO2/WHfB key credential to count as strongly authenticated, got %+v", findings)
	}
}

// TestR3StrongAuth_PrimaryGroupIDMembershipCounted covers the fact that AdminCount
// alone under-includes a just-added Domain Admin (AdminSDHolder stamps it on
// a timer) and, more sharply, never appears for a user whose primaryGroupID
// was set directly to 512 - AD adds no memberOf backlink for a user's
// PRIMARY group. This test would have FAILED against an AdminCount-only
// implementation (admin invisible, not flagged, silently excluded from the
// audit) and passes now that PrimaryGroupID is also checked.
func TestR3StrongAuth_PrimaryGroupIDMembershipCounted(t *testing.T) {
	data := &audit.DetectorData{
		IncludeDetails: true,
		Users: []types.User{
			{
				DN:                 "CN=Stealth Admin,DC=lab,DC=local",
				SAMAccountName:     "stealthadmin",
				AdminCount:         false, // not yet stamped by AdminSDHolder
				PrimaryGroupID:     512,   // Domain Admins via primary group
				UserAccountControl: 0,     // no smartcard, no key credential
			},
		},
	}
	findings := NewR3StrongAuthDetector().Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 1 {
		t.Fatalf("expected a primary-group Domain Admin without strong auth to be flagged, got %+v", findings)
	}
}
