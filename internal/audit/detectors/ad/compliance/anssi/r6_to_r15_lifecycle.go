package anssi

import (
	"strings"

	"github.com/etcsec-com/etc-collector/pkg/types"

	"github.com/etcsec-com/etc-collector/internal/audit"
)

// This file used to hold etc-collector's R6/R7/R8/R9/R14/R15 account-
// lifecycle and privileged-access hygiene detectors; each now lives in its
// own file (anssi-r6-inactive-accounts.go, anssi-r7-stale-accounts-not-
// removed.go, anssi-r8-service-accounts-as-users.go, anssi-r9-service-
// account-secret-rotation.go, anssi-r14-rbcd-audit.go, anssi-r15-tier-
// model-violation.go). What remains here is genuinely shared across many
// detectors in this package (wrapFinding/wrapFindingWithRepro/
// usersToEntities/looksLikeServiceAccount/computersToEntities/
// isWellKnownAdminTrustee), plus one piece of leftover dead code
// (protectedUsersMembers, see below).
//
// computersToEntities and isWellKnownAdminTrustee/builtinAdminSIDs moved
// here from r15_r19_r40_tier0.go and r16_to_r27_privileges_crypto.go
// respectively when those files were split one-detector-per-file: neither
// helper was used by any detector that stayed in its origin file, but both
// are used by detectors that now live in several different files
// (computersToEntities: anssi-r14-rbcd-audit.go, anssi-r19-server-core-not-
// used.go, anssi-r36-1-laps-expiry-too-long.go, anssi-r43-dc-password-
// old.go, anssi-r49-r50-mgmt-categorization.go; isWellKnownAdminTrustee:
// anssi-r12-1-force-pwd-reset-privs.go, anssi-r12-2-user-restrictions-
// privs.go), so they belong here rather than with any single detector.

func wrapFinding(d audit.Detector, title, description string, sev types.Severity, count int, entities []types.AffectedEntity) []types.Finding {
	f := types.Finding{
		Type:        d.ID(),
		Severity:    sev,
		Category:    string(d.Category()),
		Title:       title,
		Description: description,
		Count:       count,
	}
	if count > 0 && len(entities) > 0 {
		f.AffectedEntities = entities
	}
	return []types.Finding{f}
}

// wrapFindingWithRepro is identical to wrapFinding but additionally attaches
// a FindingReproducibility recipe so an ANSSI auditor can replay the LDAP
// query that produced the finding. v3.1.19 - used by R15/R19/R40/R42/R43/R69
// (LDAP-only detectors with clean reproduction paths).
func wrapFindingWithRepro(d audit.Detector, title, description string, sev types.Severity, count int, entities []types.AffectedEntity, repro *types.FindingReproducibility) []types.Finding {
	out := wrapFinding(d, title, description, sev, count, entities)
	if len(out) > 0 && repro != nil {
		out[0].Reproducibility = repro
	}
	return out
}

// looksLikeServiceAccount is a heuristic - ANSSI doesn't define a strict
// attribute for this. We flag accounts whose SAMAccountName starts with
// common service prefixes OR carry PasswordNeverExpires (classic service pattern).
func looksLikeServiceAccount(u types.User) bool {
	sam := strings.ToLower(u.SAMAccountName)
	for _, prefix := range []string{"svc", "srv", "service", "sa_", "s-", "app-"} {
		if strings.HasPrefix(sam, prefix) {
			return true
		}
	}
	return u.PasswordNeverExpires && u.ServicePrincipalNames != nil && len(u.ServicePrincipalNames) > 0
}

// protectedUsersMembers returns the lowercase DNs that are members of the
// Protected Users group. Was used by ANSSI_R11_ADMINS_NOT_IN_PROTECTED_USERS,
// removed in v3.1.21 as a dedup of the custom NOT_IN_PROTECTED_USERS check
// (mapping migrated) - this helper itself was left behind and is currently
// unused by any detector in this package. Left in place per this ticket's
// move-only constraint; noted as a needed follow-up (dead code to remove in
// a future ticket, not this one).
func protectedUsersMembers(groups []types.Group) map[string]bool {
	out := map[string]bool{}
	for _, g := range groups {
		if strings.EqualFold(g.SAMAccountName, "Protected Users") || strings.Contains(strings.ToLower(g.DN), "cn=protected users,") {
			for _, m := range g.Members {
				out[strings.ToLower(m)] = true
			}
		}
	}
	return out
}

// usersToEntities converts a slice of User to AffectedEntity, honoring
// IncludeDetails (returns nil when details shouldn't be emitted).
func usersToEntities(users []types.User, includeDetails bool) []types.AffectedEntity {
	if !includeDetails {
		return nil
	}
	out := make([]types.AffectedEntity, 0, len(users))
	for _, u := range users {
		name := u.SAMAccountName
		if name == "" {
			name = u.DisplayName
		}
		entity := types.AffectedEntity{
			Type:           "user",
			DN:             u.DN,
			SAMAccountName: u.SAMAccountName,
			Enabled:        !u.Disabled,
		}
		_ = name // reserved for future display-name fallback
		out = append(out, entity)
	}
	// Cap at 100 to keep the JSON reasonable.
	if len(out) > 100 {
		return out[:100]
	}
	return out
}

// computersToEntities converts a slice of Computer to AffectedEntity, honoring
// IncludeDetails.
//
// Uses the canonical mapper (types.ComputerToAffectedEntity, same one
// helpers.ToAffectedComputerEntities calls) instead of hand-building the
// entity: a prior local reimplementation here only set Type/DN/SAMAccountName,
// leaving Enabled/PasswordLastSet/LastLogon/MemberOf/OperatingSystem at their
// Go zero values - indistinguishable from a real disabled/unset account in
// the published JSON (caught confronting the r19 and r43 outputs).
func computersToEntities(comps []types.Computer, includeDetails bool) []types.AffectedEntity {
	if !includeDetails {
		return nil
	}
	out := make([]types.AffectedEntity, 0, len(comps))
	for i := range comps {
		out = append(out, types.ComputerToAffectedEntity(&comps[i]))
	}
	if len(out) > 100 {
		return out[:100]
	}
	return out
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
