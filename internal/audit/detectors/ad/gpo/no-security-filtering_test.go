package gpo

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

const (
	nsfDomainDN = "DC=example,DC=com"
	nsfGPODN    = "CN={nsf-gpo},CN=Policies,CN=System," + nsfDomainDN
)

// GPO_NO_SECURITY_FILTERING built hasUnrestrictedApply /
// hasSpecificFiltering from the same wrong bit (0x00010000, ADS_RIGHT_DELETE)
// as GPO_AUTHENTICATED_USERS_APPLY. A GPO where Authenticated Users can only
// DELETE (not apply) the GPO, and no one else has any grant at all, used to
// read as "unrestricted apply, no filtering" - a false positive built on a
// condition that doesn't even mean "can apply".
func TestNoSecurityFiltering_DeleteRightAloneIsNotUnrestrictedApply(t *testing.T) {
	data := &audit.DetectorData{
		GPOs: []types.GPO{
			{CN: "nsf-gpo", DistinguishedName: nsfGPODN, DisplayName: "NSF Policy"},
		},
		GPOLinks: []audit.GPOLink{
			{GPOCN: "nsf-gpo", LinkEnabled: true},
		},
		GPOAcls: []audit.GPOAcl{
			{GPODN: nsfGPODN, Trustee: sidAuthenticatedUsers, AccessMask: 0x00010000, AceType: "ACCESS_ALLOWED"},
		},
	}

	findings := NewNoSecurityFilteringDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 0 {
		t.Errorf("a DELETE-only ACE must not count as unrestricted apply, got Count=%d", findings[0].Count)
	}
}

// A genuine unrestricted Apply-Group-Policy grant to Authenticated Users,
// with no other trustee filtering it, must still be flagged.
func TestNoSecurityFiltering_UnrestrictedApplyIsFlagged(t *testing.T) {
	data := &audit.DetectorData{
		GPOs: []types.GPO{
			{CN: "nsf-gpo", DistinguishedName: nsfGPODN, DisplayName: "NSF Policy"},
		},
		GPOLinks: []audit.GPOLink{
			{GPOCN: "nsf-gpo", LinkEnabled: true},
		},
		GPOAcls: []audit.GPOAcl{
			{GPODN: nsfGPODN, Trustee: sidAuthenticatedUsers, AccessMask: types.MaskControlAccess, AceType: "ACCESS_ALLOWED"},
		},
	}

	findings := NewNoSecurityFilteringDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 1 {
		t.Errorf("an unrestricted Apply-Group-Policy grant must be flagged, got Count=%d", findings[0].Count)
	}
}

// A GPO where Authenticated Users can apply the policy, but a specific group
// also holds a real Apply-Group-Policy grant, is filtered - not flagged.
func TestNoSecurityFiltering_SpecificGroupGrantIsFiltering(t *testing.T) {
	specificGroupSID := "S-1-5-21-1-2-3-2000"

	data := &audit.DetectorData{
		GPOs: []types.GPO{
			{CN: "nsf-gpo", DistinguishedName: nsfGPODN, DisplayName: "NSF Policy"},
		},
		GPOLinks: []audit.GPOLink{
			{GPOCN: "nsf-gpo", LinkEnabled: true},
		},
		GPOAcls: []audit.GPOAcl{
			{GPODN: nsfGPODN, Trustee: sidAuthenticatedUsers, AccessMask: types.MaskControlAccess, AceType: "ACCESS_ALLOWED"},
			{GPODN: nsfGPODN, Trustee: specificGroupSID, AccessMask: types.MaskControlAccess, AceType: "ACCESS_ALLOWED"},
		},
	}

	findings := NewNoSecurityFilteringDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 0 {
		t.Errorf("a specific group holding a real Apply-Group-Policy grant should count as filtering, got Count=%d", findings[0].Count)
	}
}
