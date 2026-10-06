package adcs

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// TestADCSWeakPermissionsDetector_FiresOnNonAdminWriteDACL:
// ADCS_WEAK_PERMISSIONS read CertTemplate.HasWeakEnrollmentACL /
// HasGenericAllPermission, which are declared in pkg/types/user.go but never
// assigned anywhere in the repo (GetCertTemplates never reads a template's
// nTSecurityDescriptor) - Count was structurally always 0 regardless of the
// real ACL. Fixed by computing the same signal at read time from
// data.ACLEntries (audit.WeakACLTemplateDNs), mirroring WeakACLGPODNs /
// WeakACLCADNs - engine.go already batches CertTemplate DNs into the
// objectDNs slice passed to GetACLs, so no engine.go change is needed.
//
// The mask uses WriteDACL (a bit in weakACLDangerousMask), not the bare
// CONTROL_ACCESS/Certificate-Enrollment right: holding Enroll alone is the
// routine, expected shape for most templates and is not itself a weak ACL -
// what's dangerous is a non-admin able to rewrite the template's own DACL.
func TestADCSWeakPermissionsDetector_FiresOnNonAdminWriteDACL(t *testing.T) {
	domainSID := "S-1-5-21-1111111111-2222222222-3333333333"
	nonAdminSID := domainSID + "-9999"
	domainAdminsSID := domainSID + "-512" // privileged, must be excluded

	weakTemplateDN := "CN=WeakTemplate,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=contoso,DC=com"
	adminOnlyTemplateDN := "CN=AdminOnlyTemplate,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=contoso,DC=com"

	data := &audit.DetectorData{
		DomainInfo: &types.DomainInfo{DomainSID: domainSID},
		CertTemplates: []types.CertTemplate{
			{DN: weakTemplateDN, Name: "WeakTemplate", DisplayName: "WeakTemplate"},
			{DN: adminOnlyTemplateDN, Name: "AdminOnlyTemplate", DisplayName: "AdminOnlyTemplate"},
		},
		ACLEntries: []types.ACLEntry{
			// Non-admin holds WriteDACL on WeakTemplate - weak.
			{ObjectDN: weakTemplateDN, Trustee: nonAdminSID, AccessMask: types.MaskWriteDACL, AceType: "ACCESS_ALLOWED"},
			// Only Domain Admins hold WriteDACL on AdminOnlyTemplate - not weak.
			{ObjectDN: adminOnlyTemplateDN, Trustee: domainAdminsSID, AccessMask: types.MaskWriteDACL, AceType: "ACCESS_ALLOWED"},
		},
		IncludeDetails: true,
	}

	findings := NewADCSWeakPermissionsDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 1 {
		t.Fatalf("expected Count=1 (only WeakTemplate should fire), got %d", findings[0].Count)
	}
	if len(findings[0].AffectedEntities) != 1 || findings[0].AffectedEntities[0].SAMAccountName != "WeakTemplate" {
		t.Fatalf("expected WeakTemplate as the sole affected entity, got %+v", findings[0].AffectedEntities)
	}
}
