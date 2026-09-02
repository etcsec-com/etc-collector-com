// Package hds implements detectors specific to the French HDS v1.1 reference
// (Hébergement de Données de Santé). Most HDS technical requirements map to
// generic detectors that already exist in ETC; this file adds the few
// HDS-specific checks that have no clean home elsewhere.
//
// Reference: Référentiel HDS v1.1, ANSSI / Agence du Numérique en Santé.
// https://esante.gouv.fr/labels-certifications/hds
package hds

import (
	"context"
	"fmt"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// --- HDS 5.1.4 — Authentification forte (MFA partout pour accès aux données santé) ---
//
// Distinct from ANSSI R3 (which checks MFA on privileged accounts only): HDS
// requires MFA on every account that may touch health data, which we
// approximate as "every enabled non-service account".

type HDS514AuthForteDetector struct{ audit.BaseDetector }

func NewHDS514AuthForteDetector() *HDS514AuthForteDetector {
	return &HDS514AuthForteDetector{BaseDetector: audit.NewBaseDetector("HDS_5_1_4_STRONG_AUTH", audit.CategoryCompliance)}
}
func (d *HDS514AuthForteDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// MFA / smartcard enforcement is not observable from default AD attributes
	// in this collector; emit an informational reminder so the auditor cross-
	// checks via Entra CA, Conditional Access, or third-party MFA tooling.
	count := 0
	if len(data.Users) > 0 {
		count = 1
	}
	return wrap(d, "HDS 5.1.4 — Authentification forte à vérifier hors AD",
		"HDS 5.1.4 requires strong authentication for any account that may access health data. AD alone cannot confirm MFA enforcement; cross-check with Entra Conditional Access or third-party MFA.",
		types.SeverityInfo, count)
}

// --- HDS 5.2 — Chiffrement des données en transit (LDAPS enforced everywhere) ---

type HDS52TLSEnforcedDetector struct{ audit.BaseDetector }

func NewHDS52TLSEnforcedDetector() *HDS52TLSEnforcedDetector {
	return &HDS52TLSEnforcedDetector{BaseDetector: audit.NewBaseDetector("HDS_5_2_TLS_NOT_ENFORCED", audit.CategoryCompliance)}
}
func (d *HDS52TLSEnforcedDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// LDAP signing / channel binding aren't exposed as DomainInfo fields in
	// the current collector. Emit an informational hint pointing to the
	// LDAPS connection diagnostic the daemon performs at startup (TLSDiag).
	count := 1 // always emit so it shows up in HDS report scaffolding
	return wrap(d, "HDS 5.2 — Vérifier le chiffrement de tout le trafic AD",
		"HDS 5.2 requires strong encryption for all data in transit. Verify LDAPS-only on every DC (port 389 disabled or signing-required) and that LDAP_SIGNING / channel binding GPOs are enforced. Use 'etc-collector audit ad' TLSDiag output as evidence.",
		types.SeverityInfo, count)
}

// --- HDS 5.4 — Traçabilité des accès aux données de santé ---

type HDS54LogAccessHealthDetector struct{ audit.BaseDetector }

func NewHDS54LogAccessHealthDetector() *HDS54LogAccessHealthDetector {
	return &HDS54LogAccessHealthDetector{BaseDetector: audit.NewBaseDetector("HDS_5_4_LOG_ACCESS_TO_HEALTH_DATA", audit.CategoryCompliance)}
}
func (d *HDS54LogAccessHealthDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// Use the parsed EventAudit struct (audit.GPOPolicy.EventAudit) — value 3
	// = Both (Success+Failure), value 1 = Success only. HDS expects Both.
	hasObjectAccessAudit := false
	for _, p := range data.GPOPolicies {
		if p != nil && p.EventAudit != nil && p.EventAudit.AuditObjectAccess >= 1 {
			hasObjectAccessAudit = true
			break
		}
	}
	count := 0
	if !hasObjectAccessAudit && len(data.GPOPolicies) > 0 {
		count = 1
	}
	return wrap(d, "HDS 5.4 — Audit Object Access non configuré",
		"HDS 5.4 requires traceability of access to health data. No GPO enables 'Audit Object Access' (success+failure), making file-level access logging incomplete.",
		types.SeverityHigh, count)
}

// --- HDS 5.8 — Plan de continuité (présence d'un backup AD documenté) ---

type HDS58DRPlanDetector struct{ audit.BaseDetector }

func NewHDS58DRPlanDetector() *HDS58DRPlanDetector {
	return &HDS58DRPlanDetector{BaseDetector: audit.NewBaseDetector("HDS_5_8_DR_PLAN_MISSING", audit.CategoryCompliance)}
}
func (d *HDS58DRPlanDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// Heuristic: System State / NTBackup attribute present at the domain root?
	// In practice this is rarely populated in modern AD — rely on the
	// existence of at least 2 DCs (a single-DC forest fails DR by definition).
	dcCount := len(data.DomainControllers)
	count := 0
	if dcCount < 2 {
		count = 1
	}
	return wrap(d, "HDS 5.8 — Plan de continuité AD insuffisant",
		fmt.Sprintf("HDS 5.8 requires a documented business continuity plan with redundant infrastructure. Detected %d domain controller(s); a single-DC forest cannot satisfy HDS BCP.", dcCount),
		types.SeverityHigh, count)
}

// --- HDS 5.14 — Test périodique des mesures de sécurité (pentest cadence) ---

type HDS514PentestCadenceDetector struct{ audit.BaseDetector }

func NewHDS514PentestCadenceDetector() *HDS514PentestCadenceDetector {
	return &HDS514PentestCadenceDetector{BaseDetector: audit.NewBaseDetector("HDS_5_14_PENTEST_CADENCE", audit.CategoryCompliance)}
}
func (d *HDS514PentestCadenceDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// We have no external way to know the last pentest date — emit an
	// informational reminder only (count=1 always).
	return wrap(d, "HDS 5.14 — Vérifier la cadence de pentest annuel",
		"HDS 5.14 requires periodic testing of the security measures (typically a yearly pentest). This finding is informational — verify with your CISO that the last AD pentest is less than 12 months old.",
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
