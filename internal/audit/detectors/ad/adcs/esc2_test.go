package adcs

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

const (
	esc2TemplateDN = "CN=AnyPurpose,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=example,DC=com"
	esc2UnprivSID  = "S-1-5-21-1111111111-2222222222-3333333333-1106"
	esc2AdminSID   = "S-1-5-21-1111111111-2222222222-3333333333-519" // Enterprise Admins
)

// esc2Count runs the detector against a single template plus its enrollment
// ACEs and returns the reported count.
func esc2Count(t *testing.T, tmpl types.CertTemplate, acls []types.ACLEntry) int {
	t.Helper()
	data := &audit.DetectorData{CertTemplates: []types.CertTemplate{tmpl}, ACLEntries: acls}
	findings := NewESC2Detector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	return findings[0].Count
}

// esc2BaseVulnerable meets the pre-existing ESC2 conditions (no EKU
// constraint, no manager approval) - the old predicate flagged this
// regardless of RA-signature requirement or who can actually enroll.
func esc2BaseVulnerable() types.CertTemplate {
	return types.CertTemplate{
		DN:               esc2TemplateDN,
		Name:             "AnyPurpose",
		ExtendedKeyUsage: nil,
		EnrollmentFlag:   0,
	}
}

func TestESC2_FiresWhenFullyExploitable(t *testing.T) {
	tmpl := esc2BaseVulnerable()
	tmpl.AuthorizedSignatures = 0
	acls := []types.ACLEntry{
		{ObjectDN: esc2TemplateDN, Trustee: esc2UnprivSID, AceType: "ACCESS_ALLOWED", ObjectType: types.GUIDCertificateAutoenrollment},
	}
	if got := esc2Count(t, tmpl, acls); got != 1 {
		t.Fatalf("fully exploitable template (no RA-signature, enrollable by unprivileged) must fire: want 1, got %d", got)
	}
}

func TestESC2_SilentWhenRASignatureRequired(t *testing.T) {
	// Old predicate flagged this via the CrossCA path; msPKI-RA-Signature >= 1
	// means an enrollment agent signature is required first.
	tmpl := esc2BaseVulnerable()
	tmpl.AuthorizedSignatures = 1
	acls := []types.ACLEntry{
		{ObjectDN: esc2TemplateDN, Trustee: esc2UnprivSID, AceType: "ACCESS_ALLOWED", ObjectType: types.GUIDCertificateAutoenrollment},
	}
	if got := esc2Count(t, tmpl, acls); got != 0 {
		t.Fatalf("template requiring an RA signature is not directly exploitable: want 0, got %d", got)
	}
}

func TestESC2_SilentWhenOnlyAdminsCanEnroll(t *testing.T) {
	// Old predicate flagged this; only a privileged principal (Enterprise
	// Admins) can enroll, so this is not a privilege escalation path.
	tmpl := esc2BaseVulnerable()
	tmpl.AuthorizedSignatures = 0
	acls := []types.ACLEntry{
		{ObjectDN: esc2TemplateDN, Trustee: esc2AdminSID, AceType: "ACCESS_ALLOWED", ObjectType: types.GUIDCertificateAutoenrollment},
	}
	if got := esc2Count(t, tmpl, acls); got != 0 {
		t.Fatalf("template enrollable only by a privileged principal must not fire: want 0, got %d", got)
	}
}
