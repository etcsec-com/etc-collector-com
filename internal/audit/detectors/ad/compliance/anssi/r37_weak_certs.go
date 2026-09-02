package anssi

import (
	"context"
	"fmt"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// ANSSI-PA-099 R37 — Proscrire l'utilisation de certificats faibles ou
// vulnérables du Tier 0.
//
// Source: https://messervices.cyber.gouv.fr/documents-guides/anssi-guide-admin_securisee_si_ad_v1-0%20(3).pdf
//
// LDAP doesn't expose the issued cert key length / hash algo (those live in
// the CA database, not in AD). What we CAN audit at the AD layer is the
// certificate-template configuration, where weak / abusable settings produce
// weak Tier-0-eligible certs:
//   - templates allowing Client Authentication EKU + EnrolleeSuppliesSubject
//     (= ESC1 path, attacker can mint a cert as any user including DA)
//   - templates with the AnyPurpose EKU (over-broad usage)
//   - Smart Card Logon templates without manager approval and without
//     AuthorizedSignatures — same ESC pattern
//   - templates already flagged by the regular collector as having weak ACLs
//     (HasWeakEnrollmentACL / HasGenericAllPermission)
//
// We focus on templates whose EKUs are usable for AD authentication
// (Client Auth, Smart Card Logon, PKINIT, Any Purpose) since R37 is
// scoped to Tier 0 secrets reusability.

type R37WeakCertTemplatesDetector struct{ audit.BaseDetector }

func NewR37WeakCertTemplatesDetector() *R37WeakCertTemplatesDetector {
	return &R37WeakCertTemplatesDetector{
		BaseDetector: audit.NewBaseDetector("ANSSI_R37_WEAK_CERT_TEMPLATES", audit.CategoryCompliance),
	}
}

// authEKUs are the EKU OIDs that produce certs usable for AD authentication.
// A weak template only matters for R37 if it produces such certs.
var authEKUs = map[string]bool{
	"1.3.6.1.5.5.7.3.2":      true, // Client Authentication
	"1.3.6.1.5.2.3.4":        true, // PKINIT Client Authentication
	"1.3.6.1.4.1.311.20.2.2": true, // Smart Card Logon
	"2.5.29.37.0":            true, // Any Purpose
}

// CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT — bit 0x1 of msPKI-Certificate-Name-Flag.
// When set, the requester chooses the subject (CN/UPN), enabling ESC1.
const ctFlagEnrolleeSuppliesSubject = 0x1

func (d *R37WeakCertTemplatesDetector) Detect(_ context.Context, data *audit.DetectorData) []types.Finding {
	if len(data.CertTemplates) == 0 {
		return nil
	}

	var weak []types.CertTemplate
	var reasons []string
	for _, t := range data.CertTemplates {
		if !templateUsableForAuth(t) {
			continue
		}
		why := weaknessReasons(t)
		if len(why) == 0 {
			continue
		}
		weak = append(weak, t)
		reasons = append(reasons, t.DisplayName+": "+strings.Join(why, ", "))
	}
	if len(weak) == 0 {
		return nil
	}

	var entities []types.AffectedEntity
	if data.IncludeDetails {
		for _, t := range weak {
			entities = append(entities, types.AffectedEntity{Type: types.EntityTypeCertTemplate, DN: t.DN, Name: t.DisplayName})
		}
	}

	return wrapFinding(d, "ANSSI R37 — Weak or abusable certificate templates",
		fmt.Sprintf("%d certificate template(s) usable for AD authentication carry weaknesses that can produce attacker-controlled or over-permissive Tier 0 certs (ESC1, AnyPurpose, weak ACL): %s. ", len(weak), strings.Join(reasons, "; "))+
			"ANSSI R37 forbids weak/vulnerable Tier 0 certs — restrict EnrolleeSuppliesSubject, require manager approval for Smart Card Logon templates, and remove the AnyPurpose EKU from templates issued to privileged identities.",
		types.SeverityHigh, len(weak), entities)
}

func templateUsableForAuth(t types.CertTemplate) bool {
	for _, oid := range t.ExtendedKeyUsage {
		if authEKUs[oid] {
			return true
		}
	}
	return false
}

// weaknessReasons enumerates the abuse vectors present on a template. Empty
// slice = no weakness flagged.
func weaknessReasons(t types.CertTemplate) []string {
	var out []string
	if t.CertificateNameFlag&ctFlagEnrolleeSuppliesSubject != 0 {
		out = append(out, "EnrolleeSuppliesSubject (ESC1)")
	}
	for _, oid := range t.ExtendedKeyUsage {
		if oid == "2.5.29.37.0" {
			out = append(out, "AnyPurpose EKU")
			break
		}
	}
	if t.HasWeakEnrollmentACL {
		out = append(out, "weak enrollment ACL")
	}
	if t.HasGenericAllPermission {
		out = append(out, "GenericAll on template")
	}
	// Smart Card Logon without manager approval AND without authorized signatures
	for _, oid := range t.ExtendedKeyUsage {
		if oid == "1.3.6.1.4.1.311.20.2.2" && !t.RequiresManagerApproval && t.AuthorizedSignatures == 0 {
			out = append(out, "Smart Card Logon w/o approval")
			break
		}
	}
	// v3.1.18 — ANSSI R37 key strength: a template that allows minimum
	// key sizes below 2048 bits will issue weak certs even on a hardened CA.
	// 0 = attribute absent (template uses default — varies by template family,
	// often 1024 on legacy V1 templates), 1024 / 512 = explicitly weak.
	if t.MinKeyLength > 0 && t.MinKeyLength < 2048 {
		out = append(out, fmt.Sprintf("MinKeyLength=%d (< 2048)", t.MinKeyLength))
	}
	// v3.1.19 — Schema V1 templates with no explicit msPKI-Minimal-Key-Size
	// inherit the legacy CSP default which is typically 1024 bits. Even if
	// the modern attribute is absent, this is a real ANSSI R37 violation.
	if t.SchemaVersion == 1 && t.MinKeyLength == 0 {
		out = append(out, "Schema V1 template with no explicit MinKeyLength (CSP default = 1024 bits)")
	}
	return out
}

func init() {
	audit.MustRegister(NewR37WeakCertTemplatesDetector())
}
