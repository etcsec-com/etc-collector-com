package audit

import (
	"strings"

	"github.com/etcsec-com/etc-collector/pkg/types"
)

// builtinAdminSIDs are the non-domain principals that hold full control on
// every AD object by construction — SYSTEM, SELF, CREATOR OWNER and the
// Enterprise Domain Controllers group. Reporting them as findings describes
// Active Directory's own design, not a misconfiguration.
var builtinAdminSIDs = map[string]bool{
	"S-1-5-18": true, // LOCAL SYSTEM
	"S-1-5-10": true, // SELF
	"S-1-5-9":  true, // ENTERPRISE DOMAIN CONTROLLERS
	"S-1-3-0":  true, // CREATOR OWNER
}

// IsBuiltinAdminTrustee reports whether a trustee SID is a built-in
// administrative principal that is EXPECTED to hold dangerous rights on every
// object (T_024). ACL detectors use it to filter out AD's own baseline ACEs
// without silencing the population they exist to catch.
//
// Matching is exact for the well-known SIDs and by RID SUFFIX for privileged
// groups (types.PrivilegedSIDSuffixes) — so both the built-in domain
// (S-1-5-32-544 Administrators, -548 Account Operators, …) and each domain's
// own privileged groups (…-512 Domain Admins, …-519 Enterprise Admins, …) are
// covered, in this domain and in trusted ones.
//
// It is deliberately NOT a substring test. T_023 showed the failure mode:
// matching "s-1-5-21-" — the prefix of every domain SID — excluded every
// domain user and group, i.e. exactly the population the check targeted. The
// leading dash matters too: "…-1512" does not end with "-512".
func IsBuiltinAdminTrustee(sid string) bool {
	s := strings.ToUpper(strings.TrimSpace(sid))
	if s == "" {
		return false
	}
	if builtinAdminSIDs[s] {
		return true
	}
	for suffix := range types.PrivilegedSIDSuffixes {
		if strings.HasSuffix(s, suffix) {
			return true
		}
	}
	return false
}

// wellKnownSidInfo carries the canonical name + scope for a well-known SID.
// Scope follows the SaaS dispatcher's expectations:
//   - "WellKnown"     — universal (S-1-1-0, S-1-5-7, S-1-5-9, S-1-5-10/11/13/18/19/20)
//   - "BuiltinDomain" — S-1-5-32-* (built-in groups, identical across domains)
//   - "Domain"        — domain-specific RIDs (NOT in this table; resolved via cache)
type wellKnownSidInfo struct {
	Name  string
	Scope string
}

// wellKnownSIDs is the static lookup table required by r-asset-entities-v3_1_29-N_01 §3.
// Coverage matches the spec exactly (37 entries). Domain-specific RIDs (Domain Admins
// S-1-5-21-…-512, etc.) are intentionally absent — they're resolved via DetectorData.ObjectBySID
// because the RID prefix changes per domain.
//
// Reference: https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers
var wellKnownSIDs = map[string]wellKnownSidInfo{
	// Universal Well-Known
	"S-1-1-0":  {Name: "Everyone", Scope: "WellKnown"},
	"S-1-5-7":  {Name: "Anonymous", Scope: "WellKnown"},
	"S-1-5-9":  {Name: "Enterprise Domain Controllers", Scope: "WellKnown"},
	"S-1-5-10": {Name: "Self", Scope: "WellKnown"},
	"S-1-5-11": {Name: "Authenticated Users", Scope: "WellKnown"},
	"S-1-5-13": {Name: "Terminal Server User", Scope: "WellKnown"},
	"S-1-5-18": {Name: "Local System", Scope: "WellKnown"},
	"S-1-5-19": {Name: "Local Service", Scope: "WellKnown"},
	"S-1-5-20": {Name: "Network Service", Scope: "WellKnown"},

	// BuiltinDomain (S-1-5-32-*)
	"S-1-5-32-544": {Name: "Administrators", Scope: "BuiltinDomain"},
	"S-1-5-32-545": {Name: "Users", Scope: "BuiltinDomain"},
	"S-1-5-32-546": {Name: "Guests", Scope: "BuiltinDomain"},
	"S-1-5-32-547": {Name: "Power Users", Scope: "BuiltinDomain"},
	"S-1-5-32-548": {Name: "Account Operators", Scope: "BuiltinDomain"},
	"S-1-5-32-549": {Name: "Server Operators", Scope: "BuiltinDomain"},
	"S-1-5-32-550": {Name: "Print Operators", Scope: "BuiltinDomain"},
	"S-1-5-32-551": {Name: "Backup Operators", Scope: "BuiltinDomain"},
	"S-1-5-32-552": {Name: "Replicators", Scope: "BuiltinDomain"},
	"S-1-5-32-554": {Name: "Pre-Windows 2000 Compatible Access", Scope: "BuiltinDomain"},
	"S-1-5-32-555": {Name: "Remote Desktop Users", Scope: "BuiltinDomain"},
	"S-1-5-32-556": {Name: "Network Configuration Operators", Scope: "BuiltinDomain"},
	"S-1-5-32-557": {Name: "Incoming Forest Trust Builders", Scope: "BuiltinDomain"},
	"S-1-5-32-558": {Name: "Performance Monitor Users", Scope: "BuiltinDomain"},
	"S-1-5-32-559": {Name: "Performance Log Users", Scope: "BuiltinDomain"},
	"S-1-5-32-560": {Name: "Windows Authorization Access Group", Scope: "BuiltinDomain"},
	"S-1-5-32-561": {Name: "Terminal Server License Servers", Scope: "BuiltinDomain"},
	"S-1-5-32-562": {Name: "Distributed COM Users", Scope: "BuiltinDomain"},
	"S-1-5-32-568": {Name: "IIS_IUSRS", Scope: "BuiltinDomain"},
	"S-1-5-32-569": {Name: "Cryptographic Operators", Scope: "BuiltinDomain"},
	"S-1-5-32-573": {Name: "Event Log Readers", Scope: "BuiltinDomain"},
	"S-1-5-32-574": {Name: "Certificate Service DCOM Access", Scope: "BuiltinDomain"},
	"S-1-5-32-575": {Name: "RDS Remote Access Servers", Scope: "BuiltinDomain"},
	"S-1-5-32-576": {Name: "RDS Endpoint Servers", Scope: "BuiltinDomain"},
	"S-1-5-32-577": {Name: "RDS Management Servers", Scope: "BuiltinDomain"},
	"S-1-5-32-578": {Name: "Hyper-V Administrators", Scope: "BuiltinDomain"},
	"S-1-5-32-579": {Name: "Access Control Assistance Operators", Scope: "BuiltinDomain"},
	"S-1-5-32-580": {Name: "Remote Management Users", Scope: "BuiltinDomain"},
}

// SIDToEntity resolves a SID to either a typed wellKnownSid AffectedEntity
// (when the SID is in the static built-in table) or to an unresolved
// principal AffectedEntity. Used by detectors that have a raw SID and
// no domain-local cache to consult (or after the cache missed).
func SIDToEntity(sid string) types.AffectedEntity {
	if info, ok := wellKnownSIDs[sid]; ok {
		return types.AffectedEntity{
			Type:  types.EntityTypeWellKnownSid,
			SID:   sid,
			Name:  info.Name,
			Scope: info.Scope,
		}
	}
	return types.AffectedEntity{
		Type:       types.EntityTypePrincipal,
		SID:        sid,
		Unresolved: true,
	}
}

// SIDToEntityWithCache is the cache-aware variant. It first tries to resolve
// the SID against the domain-local ObjectBySID index (returning a typed
// user/group/computer entity), then falls back to SIDToEntity for SIDs not
// in the local domain.
func SIDToEntityWithCache(sid string, data *DetectorData) types.AffectedEntity {
	if data != nil && data.ObjectBySID != nil {
		if meta := data.ObjectBySID[sid]; meta != nil {
			return entityFromMeta(meta)
		}
	}
	return SIDToEntity(sid)
}
