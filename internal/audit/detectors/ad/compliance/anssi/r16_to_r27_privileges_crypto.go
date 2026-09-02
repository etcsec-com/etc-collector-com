package anssi

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// This file implements ANSSI PA-022 R16-R27: AdminSDHolder, sensitive built-in
// groups, and the cryptographic / signing baseline (LM hash, SMB signing, LDAP
// channel binding, Kerberos FAST armoring).
//
// R20, R21, R22 and R24 are covered by existing detectors and only need
// framework-mapping entries — see internal/audit/compliance/mappings.go.

// v3.1.21 dedup — ANSSI_R17_SCHEMA_ENTERPRISE_ADMINS_NOT_EMPTY removed.
// Custom SCHEMA_ADMINS_NOT_EMPTY is extended in this PR to also check
// Enterprise Admins, covering R17's full scope. Mapping migrated.

// --- R18: Group Policy Creator Owners minimal ---

type R18GPCOMinimalDetector struct{ audit.BaseDetector }

func NewR18GPCOMinimalDetector() *R18GPCOMinimalDetector {
	return &R18GPCOMinimalDetector{BaseDetector: audit.NewBaseDetector("ANSSI_R18_GPCO_NOT_MINIMAL", audit.CategoryCompliance)}
}
func (d *R18GPCOMinimalDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// Default is Administrator (1 member). Anything more deserves scrutiny.
	// T_129 — the finding previously reported only a bare excess count with
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
	return wrapFinding(d, "ANSSI R18 — Group Policy Creator Owners contient des membres en excès",
		"ANSSI R18 recommends keeping Group Policy Creator Owners restricted to the bare minimum. Members can create new GPOs that, once linked, can affect Tier 0 systems if cross-tier links exist.",
		types.SeverityMedium, len(excess), entities)
}

// v3.1.21 dedup — ANSSI_R19_DNSADMINS_NOT_EMPTY removed (same group as
// custom DNS_ADMINS_MEMBER). Mapping migrated.

// --- R23: LM hash storage must be disabled ---

type R23LMHashStorageDetector struct{ audit.BaseDetector }

func NewR23LMHashStorageDetector() *R23LMHashStorageDetector {
	return &R23LMHashStorageDetector{BaseDetector: audit.NewBaseDetector("ANSSI_R23_LM_HASH_NOT_DISABLED", audit.CategoryCompliance)}
}
func (d *R23LMHashStorageDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// LM hashes are stored unless NoLMHash GPO is set OR LmCompatibilityLevel >= 5
	// (which forces NTLMv2 and indirectly disables LM). Without explicit
	// NoLMHash parsing, fall back to LmCompatibilityLevel as a proxy.
	disabled := false
	for _, p := range data.GPOPolicies {
		if p == nil || p.RegistrySettings == nil {
			continue
		}
		if p.RegistrySettings.LmCompatibilityLevel != nil && *p.RegistrySettings.LmCompatibilityLevel >= 5 {
			disabled = true
			break
		}
	}
	count := 0
	if !disabled {
		count = 1
	}
	return wrapFinding(d, "ANSSI R23 — Stockage des hashes LM non désactivé",
		"ANSSI R23 requires disabling LM hash storage (NoLMHash=1 or LmCompatibilityLevel>=5). LM hashes are trivially crackable and pre-computable.",
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
	// T_129 — domain-wide GPO fact (same nature as LAPS_NOT_DEPLOYED, which
	// already points AffectedEntities at the domain object rather than a
	// per-machine list); previously always nil (motif(c)).
	var entities []types.AffectedEntity
	if count == 1 && data.IncludeDetails && data.DomainInfo != nil && data.DomainInfo.DomainDN != "" {
		entities = []types.AffectedEntity{data.EntityForDN(data.DomainInfo.DomainDN)}
	}
	return wrapFinding(d, "ANSSI R27 — Kerberos FAST armoring non activé",
		"ANSSI R27 recommends Kerberos FAST (Flexible Authentication Secure Tunneling, RFC 6113) to protect AS-REQ from offline cracking. Requires both DC-side (KDC\\SupportedEncryptionTypes/SupportedEtypes) and client-side (Kerberos\\Parameters\\RequireFast) enforcement.",
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
// EVERY domain SID — so every domain user and group was treated as a
// legitimate admin, i.e. exactly the population R12.1/R12.2 exist to catch
// (T_023). The friendly-name tokens are kept only as a fallback for callers
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
