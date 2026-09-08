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
}

// TestShadowCredentials_FiresOnUserAndComputerCombined guards the combined
// Count/AffectedEntities accounting once both populations are checked.
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
