package anssi

import (
	"context"
	"fmt"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// Phase D detectors - additional ANSSI PA-099 controls implemented in v3.1.18.
//
// Source: https://messervices.cyber.gouv.fr/documents-guides/anssi-guide-admin_securisee_si_ad_v1-0%20(3).pdf

// --- R36: CA risks affecting Tier 0 ---
//
// We approximate "Tier 0 CA risk" by flagging templates that issue certs
// usable for AD authentication AND that any of the v3.1.18 R37 weakness
// patterns apply to AND that have low-bar enrollment (RequiresManagerApproval=false).
// A CA publishing such templates is the single biggest Tier 0 PKI risk.

type R36CARisksDetector struct{ audit.BaseDetector }

func NewR36CARisksDetector() *R36CARisksDetector {
	return &R36CARisksDetector{
		BaseDetector: audit.NewBaseDetector("ANSSI_R36_CA_RISKS", audit.CategoryCompliance),
	}
}

// caCertExpiryWarnDays = a CA signing cert that expires soon must be
// renewed urgently - a lapsed CA breaks every cert-based authentication
// path. ANSSI R36 doesn't fix a number; 90 days gives the org time to
// rotate without operational pressure.
const caCertExpiryWarnDays = 90

// weakSigAlgs marks CA signing algorithms ANSSI considers obsolete for
// Tier 0 use (collision risks against modern attackers).
var weakSigAlgs = map[string]bool{
	"SHA1-RSA":   true,
	"SHA1-ECDSA": true,
	"MD5-RSA":    true,
	"DSA-SHA1":   true,
}

func (d *R36CARisksDetector) Detect(_ context.Context, data *audit.DetectorData) []types.Finding {
	// v3.1.19 - enriched check: combines CA-level signals (signing cert weak,
	// expiry imminent, weak ACL on CA object) with template-level signals
	// (ESC1 / AnyPurpose / weak key length) from v3.1.18.
	now := data.Now
	expiryThreshold := now.AddDate(0, 0, caCertExpiryWarnDays)

	// CA DNs now enter collectData's objectDNs batch
	// (internal/audit/engine.go, shared core), so
	// per-CA ACEs land in data.ACLEntries alongside every other object type.
	// CertAuthority.HasWeakACL itself stays unassigned (same read-time-not-
	// write-time choice  made for GPO.HasWeakACL): computed here via
	// WeakACLCADNs from data.ACLEntries instead of a collector-mutated
	// field, since detectors run concurrently once collectData returns and
	// mutating a shared struct from here would race.
	weakCADNs := audit.WeakACLCADNs(data)
	var caHits []string
	for _, ca := range data.CertAuthorities {
		var reasons []string
		if weakSigAlgs[ca.CACertSigAlg] {
			reasons = append(reasons, "CA cert signed with "+ca.CACertSigAlg)
		}
		if !ca.CACertNotAfter.IsZero() && ca.CACertNotAfter.Before(expiryThreshold) {
			reasons = append(reasons, fmt.Sprintf("CA cert expires %s (< %d days)", ca.CACertNotAfter.Format("2006-01-02"), caCertExpiryWarnDays))
		}
		if weakCADNs[strings.ToLower(ca.DN)] {
			reasons = append(reasons, "weak ACL on CA object (non-admins can modify)")
		}
		if len(reasons) > 0 {
			caHits = append(caHits, ca.Name+": "+strings.Join(reasons, ", "))
		}
	}

	// Template-level check (v3.1.18 logic)
	weakACLDNs := audit.WeakACLTemplateDNs(data)
	var risky []types.CertTemplate
	for _, t := range data.CertTemplates {
		if !templateUsableForAuth(t) {
			continue
		}
		if t.RequiresManagerApproval {
			continue
		}
		if len(weaknessReasons(t, weakACLDNs[strings.ToLower(t.DN)])) == 0 {
			continue
		}
		risky = append(risky, t)
	}

	if len(risky) == 0 && len(caHits) == 0 {
		return nil
	}

	// Build description combining both signals.
	parts := []string{}
	if len(caHits) > 0 {
		parts = append(parts, fmt.Sprintf("%d CA(s) carry intrinsic risk: %s", len(caHits), strings.Join(caHits, "; ")))
	}
	if len(risky) > 0 {
		parts = append(parts, fmt.Sprintf("%d certificate template(s) match an ESC pattern (R37 weakness) and are published without manager approval", len(risky)))
	}

	var entities []types.AffectedEntity
	if data.IncludeDetails {
		for _, ca := range data.CertAuthorities {
			if weakSigAlgs[ca.CACertSigAlg] || (!ca.CACertNotAfter.IsZero() && ca.CACertNotAfter.Before(expiryThreshold)) || weakCADNs[strings.ToLower(ca.DN)] {
				entities = append(entities, types.AffectedEntity{Type: "ca", DN: ca.DN, Name: ca.Name})
			}
		}
		for _, t := range risky {
			entities = append(entities, types.AffectedEntity{Type: types.EntityTypeCertTemplate, DN: t.DN, Name: t.DisplayName})
		}
	}

	count := len(risky) + len(caHits)
	return wrapFinding(d, "ANSSI R36 - Certificate authority risks affecting Tier 0",
		strings.Join(parts, ". ")+". ANSSI R36 requires addressing CA-level risks before they enable attackers to mint Tier 0 credentials. Renew expiring/SHA-1 CA certs, lock down CA ACLs, restrict risky templates (approval, remove ESC patterns).",
		types.SeverityHigh, count, entities)
}

func init() {
	audit.MustRegister(NewR36CARisksDetector())
}
