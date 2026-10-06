package critical

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

const escNonPrivilegedSID = "S-1-5-21-1-2-3-1234" // ordinary user RID, not a privileged suffix

func baseVulnerableTemplate(name string) types.CertTemplate {
	return types.CertTemplate{
		DN:                  "CN=" + name + ",CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=test,DC=local",
		Name:                name,
		CertificateNameFlag: 0x1, // ENROLLEE_SUPPLIES_SUBJECT
		ExtendedKeyUsage:    []string{"1.3.6.1.5.5.7.3.2"},
	}
}

func enrollmentACE(dn string) types.ACLEntry {
	return types.ACLEntry{
		ObjectDN:   dn,
		Trustee:    escNonPrivilegedSID,
		AceType:    "ACCESS_ALLOWED_OBJECT",
		ObjectType: types.GUIDCertificateEnrollment,
	}
}

// The official ESC1 definition (SpecterOps, "Certified Pre-Owned") covers
// any EKU usable for client authentication - Client Authentication,
// Smart Card Logon, and PKINIT Client Authentication - not Client
// Authentication alone. This test fails against the old ClientAuth-only
// check (a Smart Card Logon template is missed, Count=0) and passes once
// adcsutils.HasAuthenticationEKU is used (Count=1).
func TestCertificateEsc_DetectsSmartcardLogonEKU(t *testing.T) {
	tmpl := baseVulnerableTemplate("SmartcardTemplate")
	tmpl.ExtendedKeyUsage = []string{"1.3.6.1.4.1.311.20.2.2"} // Smart Card Logon only
	data := &audit.DetectorData{
		CertTemplates: []types.CertTemplate{tmpl},
		ACLEntries:    []types.ACLEntry{enrollmentACE(tmpl.DN)},
	}

	findings := NewCertificateEscDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1 (Smart Card Logon EKU must be caught)", findings[0].Count)
	}
}

// A template requiring manager approval is not exploitable per Certified
// Pre-Owned - flagging it Critical is a false positive. Fails against the
// old code (no approval check at all, Count=1) and passes once
// RequiresManagerApproval is checked (Count=0).
func TestCertificateEsc_ManagerApprovalIsNotVulnerable(t *testing.T) {
	tmpl := baseVulnerableTemplate("ApprovedTemplate")
	tmpl.RequiresManagerApproval = true
	data := &audit.DetectorData{
		CertTemplates: []types.CertTemplate{tmpl},
		ACLEntries:    []types.ACLEntry{enrollmentACE(tmpl.DN)},
	}

	findings := NewCertificateEscDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0 (manager approval mitigates ESC1)", findings[0].Count)
	}
}

// A template requiring authorized RA signatures is not directly
// exploitable (SpecterOps ESC1). Fails against the old code (no signature
// check, Count=1) and passes once AuthorizedSignatures is checked (Count=0).
func TestCertificateEsc_RequiredRASignatureIsNotVulnerable(t *testing.T) {
	tmpl := baseVulnerableTemplate("RASignedTemplate")
	tmpl.AuthorizedSignatures = 1
	data := &audit.DetectorData{
		CertTemplates: []types.CertTemplate{tmpl},
		ACLEntries:    []types.ACLEntry{enrollmentACE(tmpl.DN)},
	}

	findings := NewCertificateEscDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0 (required RA signature mitigates ESC1)", findings[0].Count)
	}
}

// A template only enrollable by admins (no unprivileged grant) is not a
// privilege escalation path. Fails against the old code (no enrollment ACL
// check at all, Count=1) and passes once enrollability is checked (Count=0).
func TestCertificateEsc_AdminOnlyEnrollmentIsNotVulnerable(t *testing.T) {
	tmpl := baseVulnerableTemplate("AdminOnlyTemplate")
	data := &audit.DetectorData{
		CertTemplates: []types.CertTemplate{tmpl},
		ACLEntries: []types.ACLEntry{
			{
				ObjectDN:   tmpl.DN,
				Trustee:    "S-1-5-21-1-2-3-512", // Domain Admins RID - privileged
				AceType:    "ACCESS_ALLOWED_OBJECT",
				ObjectType: types.GUIDCertificateEnrollment,
			},
		},
	}

	findings := NewCertificateEscDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0 (only admins can enroll, not a privesc path)", findings[0].Count)
	}
}

// The original ESC1 shape (ClientAuth + EnrolleeSuppliesSubject + no
// mitigations + unprivileged enrollment) must still fire - the fix must not
// silence the case the live plant/revert harness already validated
// (docs/security-validation/results/t076-runner/PATH_CERTIFICATE_ESC.md).
func TestCertificateEsc_StillDetectsUnmitigatedClientAuthTemplate(t *testing.T) {
	tmpl := baseVulnerableTemplate("VulnerableTemplate")
	data := &audit.DetectorData{
		CertTemplates: []types.CertTemplate{tmpl},
		ACLEntries:    []types.ACLEntry{enrollmentACE(tmpl.DN)},
	}

	findings := NewCertificateEscDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1 (unmitigated ESC1 template must still be caught)", findings[0].Count)
	}
}

// Mutation-coverage subtest, built from scratch (its own DN/fixture, not
// sharing baseVulnerableTemplate's/enrollmentACE's closures beyond the
// shared helper calls): a template with ENROLLEE_SUPPLIES_SUBJECT + Client
// Authentication EKU + no manager approval + no RA signature, enrollable by
// S-1-5-11 (Authenticated Users) via an ACCESS_ALLOWED_OBJECT ACE granting
// Certificate-Enrollment - a well-known built-in SID, not a generic
// unprivileged RID like the subtest above. This kills a mutation of
// condition (e) (certEnrollableByUnprivileged forced to always return
// false): that mutation leaves this subtest's fixture meeting conditions
// (a)-(d) but failing (e), so Count must drop from 1 to 0 under it.
func TestCertificateEsc_MutationCoverage(t *testing.T) {
	tmpl := types.CertTemplate{
		DN:                  "CN=T538MutationTemplate,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=contoso,DC=com",
		Name:                "T538MutationTemplate",
		CertificateNameFlag: 0x1, // ENROLLEE_SUPPLIES_SUBJECT
		ExtendedKeyUsage:    []string{"1.3.6.1.5.5.7.3.2"},
	}
	data := &audit.DetectorData{
		CertTemplates: []types.CertTemplate{tmpl},
		ACLEntries: []types.ACLEntry{
			{
				ObjectDN:   tmpl.DN,
				Trustee:    "S-1-5-11",
				AceType:    "ACCESS_ALLOWED_OBJECT",
				ObjectType: types.GUIDCertificateEnrollment,
			},
		},
	}

	findings := NewCertificateEscDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1 (weak ACL + ClientAuth + EnrolleeSuppliesSubject + S-1-5-11 enrollment grant, mirrors the live DC01 T538Vuln plant - kills_M1)", findings[0].Count)
	}
}
