package adcs

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

const (
	esc1TemplateDN = "CN=Vuln,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=example,DC=com"
	esc1UnprivSID  = "S-1-5-21-1111111111-2222222222-3333333333-1105"
	esc1AdminSID   = "S-1-5-21-1111111111-2222222222-3333333333-512" // Domain Admins
)

// esc1Count runs the detector against a single template plus its enrollment
// ACEs and returns the reported count.
func esc1Count(t *testing.T, tmpl types.CertTemplate, acls []types.ACLEntry) int {
	t.Helper()
	data := &audit.DetectorData{CertTemplates: []types.CertTemplate{tmpl}, ACLEntries: acls}
	findings := NewESC1Detector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	return findings[0].Count
}

// esc1BaseVulnerable meets the pre-existing ESC1 conditions (enrollee supplies
// subject, client auth EKU, no manager approval) - the old predicate flagged
// this regardless of RA-signature requirement or who can actually enroll.
func esc1BaseVulnerable() types.CertTemplate {
	return types.CertTemplate{
		DN:               esc1TemplateDN,
		Name:             "Vuln",
		SubjectNameFlag:  CTFlagEnrolleeSuppliesSubject,
		ExtendedKeyUsage: []string{EKUClientAuth},
		EnrollmentFlag:   0,
	}
}

func TestESC1_FiresWhenFullyExploitable(t *testing.T) {
	tmpl := esc1BaseVulnerable()
	tmpl.AuthorizedSignatures = 0
	acls := []types.ACLEntry{
		{ObjectDN: esc1TemplateDN, Trustee: esc1UnprivSID, AceType: "ACCESS_ALLOWED", ObjectType: types.GUIDCertificateEnrollment},
	}
	if got := esc1Count(t, tmpl, acls); got != 1 {
		t.Fatalf("fully exploitable template (no RA-signature, enrollable by unprivileged) must fire: want 1, got %d", got)
	}
}

func TestESC1_SilentWhenRASignatureRequired(t *testing.T) {
	// Old predicate flagged this; msPKI-RA-Signature >= 1 means an enrollment
	// agent signature is required, which is NOT directly exploitable (SpecterOps).
	tmpl := esc1BaseVulnerable()
	tmpl.AuthorizedSignatures = 1
	acls := []types.ACLEntry{
		{ObjectDN: esc1TemplateDN, Trustee: esc1UnprivSID, AceType: "ACCESS_ALLOWED", ObjectType: types.GUIDCertificateEnrollment},
	}
	if got := esc1Count(t, tmpl, acls); got != 0 {
		t.Fatalf("template requiring an RA signature is not directly exploitable: want 0, got %d", got)
	}
}

func TestESC1_SilentWhenOnlyAdminsCanEnroll(t *testing.T) {
	// Old predicate flagged this; only a privileged principal (Domain Admins)
	// can enroll, so this is not a privilege escalation path.
	tmpl := esc1BaseVulnerable()
	tmpl.AuthorizedSignatures = 0
	acls := []types.ACLEntry{
		{ObjectDN: esc1TemplateDN, Trustee: esc1AdminSID, AceType: "ACCESS_ALLOWED", ObjectType: types.GUIDCertificateEnrollment},
	}
	if got := esc1Count(t, tmpl, acls); got != 0 {
		t.Fatalf("template enrollable only by a privileged principal must not fire: want 0, got %d", got)
	}
}
