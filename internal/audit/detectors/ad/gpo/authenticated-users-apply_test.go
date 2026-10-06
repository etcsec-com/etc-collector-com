package gpo

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

const (
	auaDomainDN = "DC=example,DC=com"
	auaGPODN    = "CN={aua-gpo},CN=Policies,CN=System," + auaDomainDN
)

// GPO_AUTHENTICATED_USERS_APPLY checked AccessMask&0x00010000
// (ADS_RIGHT_DELETE) instead of the CONTROL_ACCESS + Apply-Group-Policy GUID
// extended right, so it announced "Authenticated Users can apply this GPO"
// while actually observing "Authenticated Users can DELETE it" - a rarer,
// far more serious condition, reported under the wrong name.
//
// This is the red->green proof: a DELETE-only ACE for Authenticated Users
// must NOT be flagged. Against the pre-fix constant (0x00010000) this ACE
// would have matched and the test would fail.
func TestAuthenticatedUsersApply_DeleteRightIsNotApplyGroupPolicy(t *testing.T) {
	data := &audit.DetectorData{
		GPOs: []types.GPO{
			{CN: "aua-gpo", DistinguishedName: auaGPODN, DisplayName: "AUA Policy"},
		},
		GPOLinks: []audit.GPOLink{
			{GPOCN: "aua-gpo", LinkEnabled: true},
		},
		GPOAcls: []audit.GPOAcl{
			// DELETE only - not Apply-Group-Policy.
			{GPODN: auaGPODN, Trustee: sidAuthenticatedUsers, AccessMask: 0x00010000, AceType: "ACCESS_ALLOWED"},
		},
	}

	findings := NewAuthenticatedUsersApplyDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 0 {
		t.Errorf("a DELETE-only ACE must not count as Apply-Group-Policy, got Count=%d", findings[0].Count)
	}
}

// The corrected counterpart: a genuine CONTROL_ACCESS + Apply-Group-Policy
// GUID grant on Authenticated Users must still be flagged.
func TestAuthenticatedUsersApply_RealApplyGroupPolicyGrantIsFlagged(t *testing.T) {
	data := &audit.DetectorData{
		GPOs: []types.GPO{
			{CN: "aua-gpo", DistinguishedName: auaGPODN, DisplayName: "AUA Policy"},
		},
		GPOLinks: []audit.GPOLink{
			{GPOCN: "aua-gpo", LinkEnabled: true},
		},
		GPOAcls: []audit.GPOAcl{
			{GPODN: auaGPODN, Trustee: sidAuthenticatedUsers, AccessMask: types.MaskControlAccess, AceType: "ACCESS_ALLOWED"},
		},
	}

	findings := NewAuthenticatedUsersApplyDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 1 {
		t.Errorf("a real Apply-Group-Policy grant on Authenticated Users must be flagged, got Count=%d", findings[0].Count)
	}
}

// An unlinked GPO's ACEs must not be counted, and a GPO with no
// Apply-Group-Policy grant at all must not be flagged.
func TestAuthenticatedUsersApply_NoGrantIsNotFlagged(t *testing.T) {
	data := &audit.DetectorData{
		GPOs: []types.GPO{
			{CN: "aua-gpo", DistinguishedName: auaGPODN, DisplayName: "AUA Policy"},
		},
		GPOLinks: []audit.GPOLink{
			{GPOCN: "aua-gpo", LinkEnabled: true},
		},
		GPOAcls: []audit.GPOAcl{
			{GPODN: auaGPODN, Trustee: "S-1-5-21-1-2-3-1000", AccessMask: types.MaskControlAccess, AceType: "ACCESS_ALLOWED"},
		},
	}

	findings := NewAuthenticatedUsersApplyDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 0 {
		t.Errorf("a grant to a different trustee must not be flagged, got Count=%d", findings[0].Count)
	}
}
