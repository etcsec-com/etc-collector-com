package adcs

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

const (
	esc3TemplateDN = "CN=EnrollAgent,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=example,DC=com"
	esc3UnprivSID  = "S-1-5-21-1111111111-2222222222-3333333333-1107"
	esc3AdminSID   = "S-1-5-21-1111111111-2222222222-3333333333-512" // Domain Admins
)

// esc3Count runs the detector against a single template plus its enrollment
// ACEs and returns the reported count.
func esc3Count(t *testing.T, tmpl types.CertTemplate, acls []types.ACLEntry) int {
	t.Helper()
	data := &audit.DetectorData{CertTemplates: []types.CertTemplate{tmpl}, ACLEntries: acls}
	findings := NewESC3Detector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	return findings[0].Count
}

// esc3BaseVulnerable meets the pre-existing ESC3 conditions (Certificate
// Request Agent EKU, no manager approval) - the old predicate flagged this
// regardless of RA-signature requirement or who can actually enroll.
func esc3BaseVulnerable() types.CertTemplate {
	return types.CertTemplate{
		DN:               esc3TemplateDN,
		Name:             "EnrollAgent",
		ExtendedKeyUsage: []string{EKUCertificateRequestAgent},
		EnrollmentFlag:   0,
	}
}

func TestESC3_FiresWhenFullyExploitable(t *testing.T) {
	tmpl := esc3BaseVulnerable()
	tmpl.AuthorizedSignatures = 0
	acls := []types.ACLEntry{
		{ObjectDN: esc3TemplateDN, Trustee: esc3UnprivSID, AceType: "ACCESS_ALLOWED", ObjectType: types.GUIDCertificateEnrollment},
	}
	if got := esc3Count(t, tmpl, acls); got != 1 {
		t.Fatalf("fully exploitable template (no RA-signature, enrollable by unprivileged) must fire: want 1, got %d", got)
	}
}

func TestESC3_SilentWhenRASignatureRequired(t *testing.T) {
	// Old predicate flagged this; msPKI-RA-Signature >= 1 means an enrollment
	// agent signature is required first, which is not directly exploitable.
	tmpl := esc3BaseVulnerable()
	tmpl.AuthorizedSignatures = 1
	acls := []types.ACLEntry{
		{ObjectDN: esc3TemplateDN, Trustee: esc3UnprivSID, AceType: "ACCESS_ALLOWED", ObjectType: types.GUIDCertificateEnrollment},
	}
	if got := esc3Count(t, tmpl, acls); got != 0 {
		t.Fatalf("template requiring an RA signature is not directly exploitable: want 0, got %d", got)
	}
}

func TestESC3_SilentWhenOnlyAdminsCanEnroll(t *testing.T) {
	// Old predicate flagged this; only a privileged principal (Domain Admins)
	// can enroll, so this is not a privilege escalation path.
	tmpl := esc3BaseVulnerable()
	tmpl.AuthorizedSignatures = 0
	acls := []types.ACLEntry{
		{ObjectDN: esc3TemplateDN, Trustee: esc3AdminSID, AceType: "ACCESS_ALLOWED", ObjectType: types.GUIDCertificateEnrollment},
	}
	if got := esc3Count(t, tmpl, acls); got != 0 {
		t.Fatalf("template enrollable only by a privileged principal must not fire: want 0, got %d", got)
	}
}
