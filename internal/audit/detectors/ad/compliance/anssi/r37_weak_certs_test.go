package anssi

import (
	"context"
	"strings"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// CertTemplate.HasWeakEnrollmentACL / HasGenericAllPermission are declared
// but never assigned by any provider in the repo (verified: repo-wide grep
// for both names finds only the declaration and the two read sites - this
// detector and ADCS_WEAK_PERMISSIONS, which independently hit and fixed
// the same dead-field problem via audit.WeakACLTemplateDNs). Reading those
// fields directly meant a template's weak-ACL signal could never actually
// fire. This test would have FAILED against the old implementation (a
// template with only a weak-ACL grant, no ESC1/AnyPurpose/key-length
// weakness, and no direct field write would never be flagged) and passes
// against the fix (weak ACL is computed at read time from data.ACLEntries).
func TestR37WeakCertTemplates_WeakACLGrant_Flagged(t *testing.T) {
	templateDN := "CN=WeakTemplate,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=test,DC=local"
	data := &audit.DetectorData{
		DomainInfo: &types.DomainInfo{DomainSID: "S-1-5-21-1-2-3"},
		CertTemplates: []types.CertTemplate{
			{
				DN:                      templateDN,
				DisplayName:             "WeakTemplate",
				ExtendedKeyUsage:        []string{"1.3.6.1.5.5.7.3.2"}, // Client Authentication
				MinKeyLength:            2048,                          // otherwise strong
				SchemaVersion:           2,
				AuthorizedSignatures:    1,
				RequiresManagerApproval: true,
				// HasWeakEnrollmentACL / HasGenericAllPermission intentionally
				// left at their Go zero value (false) - the dead fields.
			},
		},
		ACLEntries: []types.ACLEntry{
			{ObjectDN: templateDN, Trustee: "S-1-5-21-1-2-3-1105", AccessMask: types.MaskGenericAll, AceType: "ACCESS_ALLOWED"},
		},
	}
	d := NewR37WeakCertTemplatesDetector()
	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 1 {
		t.Fatalf("expected the weak-ACL-only template to be flagged, got %+v", findings)
	}
	if !strings.Contains(findings[0].Description, "weak") {
		t.Errorf("expected description to mention the weak ACL reason, got %q", findings[0].Description)
	}
}

func TestR37WeakCertTemplates_NoWeakness_NotFlagged(t *testing.T) {
	templateDN := "CN=StrongTemplate,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=test,DC=local"
	data := &audit.DetectorData{
		DomainInfo: &types.DomainInfo{DomainSID: "S-1-5-21-1-2-3"},
		CertTemplates: []types.CertTemplate{
			{
				DN:                      templateDN,
				DisplayName:             "StrongTemplate",
				ExtendedKeyUsage:        []string{"1.3.6.1.5.5.7.3.2"},
				MinKeyLength:            2048,
				SchemaVersion:           2,
				AuthorizedSignatures:    1,
				RequiresManagerApproval: true,
			},
		},
		ACLEntries: []types.ACLEntry{
			// Only the domain admin (privileged, excluded) holds control rights.
			{ObjectDN: templateDN, Trustee: "S-1-5-21-1-2-3-512", AccessMask: types.MaskGenericAll, AceType: "ACCESS_ALLOWED"},
		},
	}
	d := NewR37WeakCertTemplatesDetector()
	findings := d.Detect(context.Background(), data)
	if len(findings) != 0 {
		t.Fatalf("expected no finding for a template with no weakness, got %+v", findings)
	}
}
