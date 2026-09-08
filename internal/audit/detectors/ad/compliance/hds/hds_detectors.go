// Package hds implements detectors specific to the French HDS v1.1 reference
// (Hébergement de Données de Santé). Most HDS technical requirements map to
// generic detectors that already exist in ETC; this file adds the few
// HDS-specific checks that have no clean home elsewhere.
//
// Reference: Référentiel HDS Exigences, V1.1.20221027 ("en concertation"),
// Agence du Numérique en Santé. https://esante.gouv.fr/labels-certifications/hds
//
// Every detector below used to cite a specific "5.x" (or "5.x.y")
// requirement number that does not exist in this document. Verified against
// the document's own table of contents and body text: chapter 5 ("Exigences
// relatives au SMSI") is explicitly numbered to mirror ISO 27001 clauses 4-10
// and therefore starts at 5.4 and runs through 5.10 only (5.4 Contexte de
// l'organisation, 5.5 Gouvernance, 5.6 Planification, 5.7 Support, 5.8
// Fonctionnement, 5.9 Evaluation des performances, 5.10 Amélioration) - there
// is no 5.1, 5.2, 5.1.4, or 5.14 anywhere in it. The only "5.14" in the whole
// document is inside Annexe 2 ("Matrice de correspondance avec
// SecNumCloud"), where it names ISO/IEC 27001:2022 Annex A control "5.14 -
// Transferts d'information" (mapped to SecNumCloud §10.2 "Chiffrement des
// flux") - an unrelated cross-reference table entry, not an HDS exigence
// number, and nothing to do with pentest cadence. None of the five topics
// covered below (strong authentication, encryption in transit, access
// traceability, business continuity, pentest cadence) has a dedicated
// numbered HDS requirement in this document; the fabricated numbers have
// been removed rather than replaced with different invented ones. The
// detector IDs (HDS_5_1_4_STRONG_AUTH etc.) keep their fabricated-looking
// numbers because they are registered keys used outside this
// file (internal/audit/compliance/mappings.go owns them).
package hds

import (
	"context"
	"fmt"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// --- HDS - Authentification forte (MFA partout pour accès aux données santé) ---
//
// Distinct from ANSSI R3 (which checks MFA on privileged accounts only): HDS
// certification expects MFA on every account that may touch health data,
// which we approximate as "every enabled non-service account".

type HDS514AuthForteDetector struct{ audit.BaseDetector }

func NewHDS514AuthForteDetector() *HDS514AuthForteDetector {
	return &HDS514AuthForteDetector{BaseDetector: audit.NewBaseDetector("HDS_5_1_4_STRONG_AUTH", audit.CategoryCompliance)}
}
func (d *HDS514AuthForteDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// MFA / smartcard enforcement is not observable from default AD attributes
	// in this collector; emit an informational reminder so the auditor cross-
	// checks via Entra CA, Conditional Access, or third-party MFA tooling.
	//
	// Previously gated on len(data.Users) > 0 - that's a test that
	// user data was collected at all, not a measurement of authentication
	// strength (any real audit has users, so this was functionally always
	// "1" while pretending to be data-driven). Made unconditional, matching
	// the honest "standing reminder" pattern used by the sibling checks
	// below (and by industry.AuditLogRetentionDetector /
	// DataClassificationDetector for the same "cannot verify via LDAP"
	// shape of advisory).
	return wrap(d, "HDS - Authentification forte à vérifier hors AD",
		"Strong authentication for accounts accessing health data is a standard expectation of HDS-certified environments. Référentiel HDS Exigences V1.1.20221027 does not set this out as a specific numbered requirement (its chapter 5 covers ISMS governance/process clauses 5.4-5.10, not per-topic technical controls). AD alone cannot confirm MFA enforcement; cross-check with Entra Conditional Access or third-party MFA.",
		types.SeverityInfo, 1)
}

// --- HDS - Chiffrement des données en transit (LDAPS enforced everywhere) ---

type HDS52TLSEnforcedDetector struct{ audit.BaseDetector }

func NewHDS52TLSEnforcedDetector() *HDS52TLSEnforcedDetector {
	return &HDS52TLSEnforcedDetector{BaseDetector: audit.NewBaseDetector("HDS_5_2_TLS_NOT_ENFORCED", audit.CategoryCompliance)}
}
func (d *HDS52TLSEnforcedDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// LDAP signing / channel binding aren't exposed as DomainInfo fields in
	// the current collector. Emit an informational hint pointing to the
	// LDAPS connection diagnostic the daemon performs at startup (TLSDiag).
	count := 1 // always emit so it shows up in HDS report scaffolding
	return wrap(d, "HDS - Vérifier le chiffrement de tout le trafic AD",
		"Encryption of data in transit is a standard expectation of HDS-certified environments. Référentiel HDS Exigences V1.1.20221027 does not set this out as a specific numbered chapter-5 requirement - the only related mention anywhere in the document is Annexe 2's SecNumCloud cross-reference matrix, where ISO 27001 Annex A control 5.14 'Transferts d'information' maps to SecNumCloud §10.2 'Chiffrement des flux' (a mapping-matrix entry, not an HDS exigence). Verify LDAPS-only on every DC (port 389 disabled or signing-required) and that LDAP_SIGNING / channel binding GPOs are enforced. Use 'etc-collector audit ad' TLSDiag output as evidence.",
		types.SeverityInfo, count)
}

// --- HDS - Traçabilité des accès aux données de santé ---

type HDS54LogAccessHealthDetector struct{ audit.BaseDetector }

func NewHDS54LogAccessHealthDetector() *HDS54LogAccessHealthDetector {
	return &HDS54LogAccessHealthDetector{BaseDetector: audit.NewBaseDetector("HDS_5_4_LOG_ACCESS_TO_HEALTH_DATA", audit.CategoryCompliance)}
}
func (d *HDS54LogAccessHealthDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// Use the parsed EventAudit struct (audit.GPOPolicy.EventAudit) - value 3
	// = Both (Success+Failure), value 1 = Success only, value 2 = Failure
	// only. HDS expects Both - the old ">= 1" threshold accepted a
	// Success-only or Failure-only GPO as satisfying this, silently
	// producing false negatives on a domain that audits only successes (or
	// only failures) rather than both, contradicting the finding's own
	// description below. Fixed to require the Both value exactly.
	hasObjectAccessAudit := false
	for _, p := range data.GPOPolicies {
		if p != nil && p.EventAudit != nil && p.EventAudit.AuditObjectAccess >= 3 {
			hasObjectAccessAudit = true
			break
		}
	}
	count := 0
	if !hasObjectAccessAudit && len(data.GPOPolicies) > 0 {
		count = 1
	}
	return wrap(d, "HDS - Audit Object Access non configuré (Success et Failure)",
		"Traceability of access to health data is a standard expectation of HDS-certified environments. Référentiel HDS Exigences V1.1.20221027 does not set this out as a specific numbered chapter-5 requirement (chapter 5 covers generic ISMS process clauses 5.4-5.10; the closest related mentions are the risk-factor list in §5.6.1.2 and the audit obligation in §5.9.2, neither of which mandates this specific GPO setting). No GPO enables 'Audit Object Access' for both Success and Failure, leaving file-level access logging incomplete.",
		types.SeverityHigh, count)
}

// --- HDS - Plan de continuité (présence d'un backup AD documenté) ---

type HDS58DRPlanDetector struct{ audit.BaseDetector }

func NewHDS58DRPlanDetector() *HDS58DRPlanDetector {
	return &HDS58DRPlanDetector{BaseDetector: audit.NewBaseDetector("HDS_5_8_DR_PLAN_MISSING", audit.CategoryCompliance)}
}
func (d *HDS58DRPlanDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// Heuristic: System State / NTBackup attribute present at the domain root?
	// In practice this is rarely populated in modern AD - rely on the
	// existence of at least 2 DCs (a single-DC forest fails DR by definition).
	dcCount := len(data.DomainControllers)
	count := 0
	if dcCount < 2 {
		count = 1
	}
	return wrap(d, "HDS - Plan de continuité AD insuffisant (heuristique)",
		fmt.Sprintf("A documented business continuity plan is a standard expectation of HDS-certified environments. Référentiel HDS Exigences V1.1.20221027 does not set this out as a specific numbered chapter-5 requirement (5.8 'Fonctionnement' is generic ISO 27001-style operational/risk-treatment planning, not a business-continuity mandate). HEURISTIC, not a direct measurement: this check uses domain-controller count as a rough, AD-observable proxy - a domain with %d co-located domain controller(s) and no real DR plan would still pass at >=2, while a well-planned single-DC deployment with off-domain backups still fails here. Treat as a prompt to verify manually, not a confirmed absence of continuity planning.", dcCount),
		types.SeverityHigh, count)
}

// --- HDS - Test périodique des mesures de sécurité (pentest cadence) ---

type HDS514PentestCadenceDetector struct{ audit.BaseDetector }

func NewHDS514PentestCadenceDetector() *HDS514PentestCadenceDetector {
	return &HDS514PentestCadenceDetector{BaseDetector: audit.NewBaseDetector("HDS_5_14_PENTEST_CADENCE", audit.CategoryCompliance)}
}
func (d *HDS514PentestCadenceDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// We have no external way to know the last pentest date - emit an
	// informational reminder only (count=1 always).
	return wrap(d, "HDS - Vérifier la cadence de pentest annuel",
		"Periodic security testing (e.g. an annual penetration test) is part of the continuous-improvement process HDS-certified environments are expected to run (Référentiel HDS Exigences V1.1.20221027 §5.9 Evaluation des performances / §5.10 Amélioration), but the document does not set a specific numbered pentest-cadence requirement - this finding is purely informational. Verify with your CISO that the last AD pentest is less than 12 months old.",
		types.SeverityInfo, 1)
}

// --- shared helpers ---

func wrap(d audit.Detector, title, description string, sev types.Severity, count int) []types.Finding {
	return []types.Finding{{
		Type:        d.ID(),
		Severity:    sev,
		Category:    string(d.Category()),
		Title:       title,
		Description: description,
		Count:       count,
	}}
}

func init() {
	audit.MustRegister(NewHDS514AuthForteDetector())
	audit.MustRegister(NewHDS52TLSEnforcedDetector())
	audit.MustRegister(NewHDS54LogAccessHealthDetector())
	audit.MustRegister(NewHDS58DRPlanDetector())
	audit.MustRegister(NewHDS514PentestCadenceDetector())
}
