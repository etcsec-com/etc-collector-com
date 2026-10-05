package critical

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	adcsutils "github.com/etcsec-com/etc-collector/internal/audit/detectors/ad/adcs"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// CertificateEscDetector detects ADCS certificate template paths to Domain
// Admin (ESC1 - SpecterOps, "Certified Pre-Owned", Schroeder & Christensen,
// 2021).
//
// Source check corrected against the official ESC1 definition:
//   - False negatives fixed: the official definition covers any EKU usable
//     for client authentication (Client Authentication 1.3.6.1.5.5.7.3.2,
//     Smart Card Logon 1.3.6.1.4.1.311.20.2.2, PKINIT Client Authentication
//     1.3.6.1.5.2.3.4), not Client Authentication alone. Uses
//     adcsutils.HasAuthenticationEKU - the same helper the repo's own
//     ESC1_VULNERABLE_TEMPLATE detector (ad/adcs/esc1.go) already uses for
//     this exact check.
//   - False positives fixed: per Certified Pre-Owned, ESC1 requires manager
//     approval AND authorized-RA-signatures to both be off, AND enrollment
//     to actually be reachable by a non-privileged principal. A template
//     with any one of those mitigations is not exploitable and must not be
//     Critical.
type CertificateEscDetector struct {
	audit.BaseDetector
}

// NewCertificateEscDetector creates a new detector
func NewCertificateEscDetector() *CertificateEscDetector {
	return &CertificateEscDetector{
		BaseDetector: audit.NewBaseDetector("PATH_CERTIFICATE_ESC", audit.CategoryAttackPaths),
	}
}

// certEnrollmentGenericAll - GENERIC_ALL, used the same way
// adcs/utils.go's templateEnrollableByUnprivileged treats a full-control
// grant as implying enrollment rights.
const certEnrollmentGenericAll = 0x10000000

// Detect executes the detection
func (d *CertificateEscDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var vulnerableTemplates []string

	for _, t := range data.CertTemplates {
		// ESC1: enrollee supplies subject + an EKU usable for client
		// authentication + no manager approval + no authorized-RA-signature
		// requirement + actually enrollable by a non-privileged principal.
		enrolleeSupplies := (t.CertificateNameFlag & 0x1) != 0
		hasAuthEKU := adcsutils.HasAuthenticationEKU(t.ExtendedKeyUsage)
		noApprovalRequired := !t.RequiresManagerApproval
		noRASignatureRequired := t.AuthorizedSignatures == 0
		enrollableByUnprivileged := certEnrollableByUnprivileged(t.DN, data.ACLEntries)

		if enrolleeSupplies && hasAuthEKU && noApprovalRequired &&
			noRASignatureRequired && enrollableByUnprivileged {
			name := t.Name
			if name == "" {
				name = t.DisplayName
			}
			vulnerableTemplates = append(vulnerableTemplates, name)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityCritical,
		Category:    string(d.Category()),
		Title:       "Certificate Template Escalation to Domain Admin",
		Description: "Vulnerable certificate templates (ESC1-like) allow users to request certificates for any user including Domain Admins.",
		Count:       len(vulnerableTemplates),
	}

	if data.IncludeDetails && len(vulnerableTemplates) > 0 {
		entities := make([]types.AffectedEntity, len(vulnerableTemplates))
		for i, name := range vulnerableTemplates {
			entities[i] = types.AffectedEntity{
				Type:           "certTemplate",
				SAMAccountName: name,
			}
		}
		finding.AffectedEntities = entities
		finding.Details = map[string]interface{}{
			"vulnerableTemplates": vulnerableTemplates,
			"attackVector":        "Enroll in vulnerable template → Request cert as DA → Authenticate as DA",
			"mitigation":          "Disable ENROLLEE_SUPPLIES_SUBJECT flag, restrict enrollment permissions, use Certificate Manager Approval",
		}
	}

	return []types.Finding{finding}
}

// certEnrollableByUnprivileged reports whether a non-privileged principal
// holds an enrollment right (Certificate-Enrollment, Certificate-AutoEnrollment,
// or a full-control grant) on the certificate template at dn - mirroring
// adcs/utils.go's templateEnrollableByUnprivileged (which this package
// cannot import: it is unexported and out of scope here),
// but checking AceType via audit.IsGrantACE instead of a literal "deny"
// string comparison the AceType field never actually contains
// ("ACCESS_DENIED"/"ACCESS_DENIED_OBJECT" per acl_parser.go).
func certEnrollableByUnprivileged(dn string, acls []types.ACLEntry) bool {
	for _, acl := range acls {
		if acl.ObjectDN != dn || !audit.IsGrantACE(acl.AceType) {
			continue
		}

		grantsEnrollment := acl.ObjectType == types.GUIDCertificateEnrollment ||
			acl.ObjectType == types.GUIDCertificateAutoenrollment ||
			(acl.AccessMask&certEnrollmentGenericAll) != 0
		if !grantsEnrollment {
			continue
		}

		if !audit.IsPrivilegedSID(acl.Trustee) {
			return true
		}
	}
	return false
}

func init() {
	audit.MustRegister(NewCertificateEscDetector())
}
