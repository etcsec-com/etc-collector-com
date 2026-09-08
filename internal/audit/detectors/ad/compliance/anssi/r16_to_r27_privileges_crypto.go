package anssi

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// This file implements etc-collector's AdminSDHolder / sensitive built-in
// group and cryptographic-baseline detectors (LM/NTLM hardening, Kerberos
// FAST armoring). Despite the "R16-R27" filename (kept for history), a
// full-text audit of ANSSI PA-099 found these IDs do NOT correspond
// to PA-099 recommendations R16-R27 - see each detector's own comment for
// what the real PA-099 content at that number is, and the correct citation
// where one exists.
//
// R20, R21, R22 and R24 are covered by existing detectors and only need
// framework-mapping entries - see internal/audit/compliance/mappings.go.

// v3.1.21 dedup - ANSSI_R17_SCHEMA_ENTERPRISE_ADMINS_NOT_EMPTY removed.
// Custom SCHEMA_ADMINS_NOT_EMPTY is extended in this PR to also check
// Enterprise Admins, covering R17's full scope. Mapping migrated.

// --- R18: Group Policy Creator Owners minimal ---

type R18GPCOMinimalDetector struct{ audit.BaseDetector }

func NewR18GPCOMinimalDetector() *R18GPCOMinimalDetector {
	return &R18GPCOMinimalDetector{BaseDetector: audit.NewBaseDetector("ANSSI_R18_GPCO_NOT_MINIMAL", audit.CategoryCompliance)}
}
func (d *R18GPCOMinimalDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// Default is Administrator (1 member). Anything more deserves scrutiny.
	// The finding previously reported only a bare excess count with
	// no AffectedEntities (motif(c)), which last night's harness confirmed
	// live is inactionable (entity_present=0, unattributable). Members beyond
	// the default Administrator are now resolved and listed.
	var excess []types.AffectedEntity
	for _, g := range data.Groups {
		if !strings.EqualFold(g.SAMAccountName, "Group Policy Creator Owners") {
			continue
		}
		for _, memberDN := range g.Members {
			entity := data.EntityForDN(memberDN)
			if strings.EqualFold(entity.SAMAccountName, "Administrator") {
				continue
			}
			excess = append(excess, entity)
		}
	}
	var entities []types.AffectedEntity
	if data.IncludeDetails {
		entities = excess
	}
	// ANSSI PA-099 (full-text source audit): "Group Policy Creator Owners"
	// (or its French name) does not appear anywhere in PA-099's 166 pages.
	// The real R18 is "Appliquer les security baselines aux systèmes du
	// Tier 0" (p.35, Microsoft/CIS-style OS hardening baselines) - unrelated
	// to this AD group. Keeping Group Policy Creator Owners minimal is a
	// recognized general AD hygiene practice, not an ANSSI PA-099 citation.
	return wrapFinding(d, "Group Policy Creator Owners contient des membres en excès (heuristic)",
		"Group Policy Creator Owners should be restricted to the bare minimum. Members can create new GPOs that, once linked, can affect Tier 0 systems if cross-tier links exist. This is a general AD hygiene heuristic; no ANSSI PA-099 recommendation names this specific group.",
		types.SeverityMedium, len(excess), entities)
}

// v3.1.21 dedup - ANSSI_R19_DNSADMINS_NOT_EMPTY removed (same group as
// custom DNS_ADMINS_MEMBER). Mapping migrated.

// --- R23: LM hash storage must be disabled ---

type R23LMHashStorageDetector struct{ audit.BaseDetector }

func NewR23LMHashStorageDetector() *R23LMHashStorageDetector {
	return &R23LMHashStorageDetector{BaseDetector: audit.NewBaseDetector("ANSSI_R23_LM_HASH_NOT_DISABLED", audit.CategoryCompliance)}
}
func (d *R23LMHashStorageDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// ANSSI PA-099 (full-text source audit) R72 (p.97-98) mandates, via
	// GPO path "Configuration ordinateur\Paramètres Windows\Paramètres de
	// sécurité\Stratégies locales\Options de sécurité\Sécurité Réseau",
	// setting "Niveau d'authentification LAN Manager" to "Envoyer uniquement
	// une réponse NTLM version 2 et refuser LM et NTLM" - exactly
	// LmCompatibilityLevel=5. That is what this detector actually reads.
	// (The real R23 in PA-099 is unrelated: "Contrôler les permissions
	// appliquées aux comptes et groupes de Tier 0" - adminSDHolder/ACL
	// hygiene, p.40.) NoLMHash (SAM hash-storage suppression) is a distinct
	// Windows setting this guide never mentions; LmCompatibilityLevel
	// governs the LAN Manager authentication LEVEL, not hash storage, and
	// is used here only because it's the setting PA-099 R72 actually names.
	compliant := false
	for _, p := range data.GPOPolicies {
		if p == nil || p.RegistrySettings == nil {
			continue
		}
		if p.RegistrySettings.LmCompatibilityLevel != nil && *p.RegistrySettings.LmCompatibilityLevel >= 5 {
			compliant = true
			break
		}
	}
	count := 0
	if !compliant {
		count = 1
	}
	return wrapFinding(d, "ANSSI PA-099 R72 - Niveau d'authentification LAN Manager non durci",
		"ANSSI PA-099 R72 (p.97-98) requires \"Niveau d'authentification LAN Manager\" set to \"Envoyer uniquement une réponse NTLM version 2 et refuser LM et NTLM\" (LmCompatibilityLevel=5) on every AD-member system. Below level 5, legacy LM/NTLMv1 responses remain negotiable and are trivially crackable.",
		types.SeverityHigh, count, nil)
}

// --- R27: Kerberos pre-auth FAST armoring ---

type R27KerberosFASTArmoringDetector struct{ audit.BaseDetector }

func NewR27KerberosFASTArmoringDetector() *R27KerberosFASTArmoringDetector {
	return &R27KerberosFASTArmoringDetector{BaseDetector: audit.NewBaseDetector("ANSSI_R27_KERBEROS_PREAUTH_NOT_FAST", audit.CategoryCompliance)}
}
func (d *R27KerberosFASTArmoringDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	dc, client := false, false
	for _, p := range data.GPOPolicies {
		if p == nil || p.RegistrySettings == nil {
			continue
		}
		if p.RegistrySettings.KerberosArmoringDC != nil && *p.RegistrySettings.KerberosArmoringDC >= 1 {
			dc = true
		}
		if p.RegistrySettings.KerberosArmoringClient != nil && *p.RegistrySettings.KerberosArmoringClient >= 1 {
			client = true
		}
	}
	count := 0
	if !dc || !client {
		count = 1
	}
	// Domain-wide GPO fact (same nature as LAPS_NOT_DEPLOYED, which
	// already points AffectedEntities at the domain object rather than a
	// per-machine list); previously always nil (motif(c)).
	var entities []types.AffectedEntity
	if count == 1 && data.IncludeDetails && data.DomainInfo != nil && data.DomainInfo.DomainDN != "" {
		entities = []types.AffectedEntity{data.EntityForDN(data.DomainInfo.DomainDN)}
	}
	// ANSSI PA-099 (full-text source audit) R68 (p.93-94), "Activer le
	// blindage Kerberos sur les systèmes du Tier 0", requires BOTH:
	//  - client-side, GPO path Configuration ordinateur\Modèles
	//    d'administration\Système\Kerberos, "Prise en charge du client
	//    Kerberos pour les revendications, l'authentification composée et
	//    le blindage Kerberos: Activé" - parsed into KerberosArmoringClient
	//    (registrypol_parser.go: RequireFast);
	//  - DC-side, GPO path ...\Système\KDC, "Prise en charge du contrôleur
	//    de domaine Kerberos pour les revendications...: Activé avec la
	//    valeur 'Pris en charge'" - the real GPO value name is
	//    EnableCbacAndArmor under a Kdc-shaped key, parsed into
	//    KerberosArmoringDC. (The real R27 in PA-099 is unrelated: regularly
	//    running AD control-path analysis tools, e.g. BloodHound, p.43.)
	return wrapFinding(d, "ANSSI PA-099 R68 - Blindage Kerberos (FAST) non activé sur le Tier 0",
		"ANSSI PA-099 R68 (p.93-94) requires Kerberos armoring (\"blindage Kerberos\", RFC 6113 FAST) enabled on Tier 0 systems, both client-side (EnableCbacAndArmor / RequireFast) and DC-side (KDC EnableCbacAndArmor).",
		types.SeverityMedium, count, entities)
}

// builtinAdminSIDs are the non-domain well-known principals that legitimately
// hold rights on every object. Domain-relative privileged groups (Domain
// Admins, Enterprise Admins, …) are matched by RID suffix instead, via the
// shared types.PrivilegedSIDSuffixes table.
var builtinAdminSIDs = map[string]bool{
	"S-1-5-18": true, // LOCAL SYSTEM
	"S-1-5-10": true, // SELF
	"S-1-5-9":  true, // ENTERPRISE DOMAIN CONTROLLERS
	"S-1-3-0":  true, // CREATOR OWNER
}

// isWellKnownAdminTrustee returns true for built-in principals that legitimately
// hold write rights on sensitive AD objects (AdminSDHolder, ACEs, etc.).
//
// Trustees arrive as SIDs (acl_parser.go:331), so the match is SID-based. The
// previous version also matched the bare substring "s-1-5-21-", the prefix of
// EVERY domain SID - so every domain user and group was treated as a
// legitimate admin, i.e. exactly the population R12.1/R12.2 exist to catch
// in the first place. The friendly-name tokens are kept only as a fallback for callers
// that pass a resolved name rather than a SID.
func isWellKnownAdminTrustee(trustee string) bool {
	t := strings.ToUpper(strings.TrimSpace(trustee))

	if strings.HasPrefix(t, "S-1-") {
		if builtinAdminSIDs[t] {
			return true
		}
		// Privileged RID suffixes: -512 Domain Admins, -519 Enterprise Admins,
		// -518 Schema Admins, -544 BUILTIN\Administrators, etc.
		for suffix := range types.PrivilegedSIDSuffixes {
			if strings.HasSuffix(t, suffix) {
				return true
			}
		}
		return false
	}

	name := strings.ToLower(t)
	for _, known := range []string{
		"domain admins", "enterprise admins", "schema admins", "administrators",
		"system", "self", "creator owner",
	} {
		if strings.Contains(name, known) {
			return true
		}
	}
	return false
}

func init() {
	audit.MustRegister(NewR18GPCOMinimalDetector())
	audit.MustRegister(NewR23LMHashStorageDetector())
	audit.MustRegister(NewR27KerberosFASTArmoringDetector())
}
