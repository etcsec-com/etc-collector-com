package anssi

import (
	"context"
	"fmt"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// This file implements etc-collector's account-lifecycle and privileged-
// access hygiene layer for AD. Despite the "R6-R15" filename (kept for
// history), most of these IDs do NOT correspond to ANSSI PA-099
// recommendations R6-R15: a full-text audit of PA-099 found that
// R6/R7/R8/R9/R14/R15 in the actual guide cover entirely different topics
// (attack-path analysis, Tier categorization, functional levels, etc. - see
// each detector's own comment for the real PA-099 content at that number).
// Where a genuine ANSSI source exists for what a detector measures, it is
// cited precisely (guide, recommendation, page); where none exists, the
// finding is described as a product benchmark, not an ANSSI requirement.
//
//   R6  - Comptes inactifs non désactivés (product benchmark, 90j)
//   R7  - Comptes stales non supprimés (product benchmark, 180j)
//   R8  - Comptes de service distincts des comptes nominatifs (heuristic)
//   R9  - Rotation des secrets des comptes de service (product benchmark, 1 an)
//   R10 - Désactivation de la pré-authentification uniquement sur demande documentée
//   R11 - Protection des comptes à privilèges par Protected Users
//   R12 - Restriction des droits de réplication (DCSync)
//   R13 - Proscription de la délégation non contrainte
//   R14 - RBCD sur un contrôleur de domaine (ANSSI PA-099 R65, p.90-91)
//   R15 - Comptes admin hors OU Tier 0 dédiée (ANSSI PA-099 R58, p.73-74)
//
// Each detector follows the same compact pattern: one struct, a constructor
// that sets the stable ID, and a Detect method that queries DetectorData
// and emits a single Finding. Registration happens in this file's init().

// --- R6: Comptes inactifs non désactivés ---

type R6InactiveAccountsDetector struct{ audit.BaseDetector }

func NewR6InactiveAccountsDetector() *R6InactiveAccountsDetector {
	return &R6InactiveAccountsDetector{BaseDetector: audit.NewBaseDetector("ANSSI_R6_INACTIVE_ACCOUNTS", audit.CategoryCompliance)}
}
func (d *R6InactiveAccountsDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	threshold := data.Now.AddDate(0, 0, -90)
	var affected []types.User
	for _, u := range data.Users {
		if u.Disabled {
			continue
		}
		last := u.LastLogonTimestamp
		if u.LastLogon.After(last) {
			last = u.LastLogon
		}
		if !last.IsZero() && last.Before(threshold) {
			affected = append(affected, u)
		}
	}
	// ANSSI PA-099 (full-text source audit): the real R6 is "Analyser les
	// chemins d'attaque vers le Tier 0 et le Tier 1" (p.21-22), an
	// attack-path-analysis step, not an inactivity threshold - and no
	// inactivity-day figure of any kind appears anywhere in that 166-page
	// guide. The 90-day threshold below is etc-collector's own product
	// benchmark, not an ANSSI-mandated number.
	return wrapFinding(d, "Comptes inactifs non désactivés (90j, product benchmark)",
		"Accounts inactive for more than 90 days should be disabled to reduce the attack surface. 90 days is etc-collector's product benchmark; no ANSSI PA-099 recommendation prescribes this figure.",
		types.SeverityMedium, len(affected), usersToEntities(affected, data.IncludeDetails))
}

// --- R7: Comptes stales > 180j non supprimés ---

type R7StaleAccountsNotRemovedDetector struct{ audit.BaseDetector }

func NewR7StaleAccountsNotRemovedDetector() *R7StaleAccountsNotRemovedDetector {
	return &R7StaleAccountsNotRemovedDetector{BaseDetector: audit.NewBaseDetector("ANSSI_R7_STALE_ACCOUNTS_NOT_REMOVED", audit.CategoryCompliance)}
}
func (d *R7StaleAccountsNotRemovedDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	threshold := data.Now.AddDate(0, 0, -180)
	var affected []types.User
	for _, u := range data.Users {
		if !u.Disabled {
			continue
		}
		last := u.LastLogonTimestamp
		if u.LastLogon.After(last) {
			last = u.LastLogon
		}
		// A disabled account that has NEVER logged on has no LastLogon/
		// LastLogonTimestamp at all (both zero) - it used to be silently
		// skipped here (the `!last.IsZero()` guard excluded it), which
		// let the worst case (created, disabled, never legitimately used,
		// lingering indefinitely) go unflagged forever. Fall back to
		// Created (whenCreated) so a never-used disabled account is judged
		// on how long it's existed instead of disappearing from this check.
		if last.IsZero() {
			last = u.Created
		}
		if !last.IsZero() && last.Before(threshold) {
			affected = append(affected, u)
		}
	}
	// ANSSI PA-099 (full-text source audit): the real R7 is "Catégoriser les
	// ressources du SI en Tiers" (p.22-23), a Tier-classification
	// methodology step, not a stale-account removal rule - no 180-day (or
	// any) removal threshold appears anywhere in the guide. This is
	// etc-collector's own product benchmark.
	return wrapFinding(d, "Comptes stales (180j+) non supprimés (product benchmark)",
		"Disabled accounts unused for 180+ days should be deleted to reduce directory bloat and the risk of unnoticed reactivation. 180 days is etc-collector's own product benchmark; no ANSSI PA-099 recommendation prescribes this figure.",
		types.SeverityLow, len(affected), usersToEntities(affected, data.IncludeDetails))
}

// --- R8: Comptes de service utilisés comme comptes nominatifs ---

type R8ServiceAccountsAsUsersDetector struct{ audit.BaseDetector }

func NewR8ServiceAccountsAsUsersDetector() *R8ServiceAccountsAsUsersDetector {
	return &R8ServiceAccountsAsUsersDetector{BaseDetector: audit.NewBaseDetector("ANSSI_R8_SERVICE_ACCOUNTS_AS_USERS", audit.CategoryCompliance)}
}
func (d *R8ServiceAccountsAsUsersDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.User
	for _, u := range data.Users {
		if u.Disabled {
			continue
		}
		// Heuristic: a service account that also has a mailbox or an HR-style
		// attribute (title, department) likely blurs the nominative/service line.
		if looksLikeServiceAccount(u) && (u.Mail != "" || u.Title != "" || u.Department != "") {
			affected = append(affected, u)
		}
	}
	// ANSSI PA-099 (full-text source audit): the real R8 is "Cloisonner
	// l'administration de chaque Tier" (p.25) - dedicated admin accounts per
	// Tier, not "service accounts must be distinct from nominative
	// accounts". No R-number in PA-099 states that specific rule; this is a
	// recognized general AD hygiene practice, not an ANSSI PA-099 citation.
	return wrapFinding(d, "Comptes de service indistincts des comptes nominatifs (heuristic)",
		"Service accounts should be clearly separated from nominative accounts (no mailbox, no HR attributes). Shared hybrids hide privilege and muddy audit trails. This is a general AD hygiene heuristic, not an ANSSI PA-099 requirement.",
		types.SeverityMedium, len(affected), usersToEntities(affected, data.IncludeDetails))
}

// --- R9: Secrets des comptes de service non rotés (>1 an) ---

type R9ServiceAccountSecretRotationDetector struct{ audit.BaseDetector }

func NewR9ServiceAccountSecretRotationDetector() *R9ServiceAccountSecretRotationDetector {
	return &R9ServiceAccountSecretRotationDetector{BaseDetector: audit.NewBaseDetector("ANSSI_R9_SERVICE_ACCOUNT_SECRET_ROTATION", audit.CategoryCompliance)}
}
func (d *R9ServiceAccountSecretRotationDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	threshold := data.Now.AddDate(-1, 0, 0)
	var affected []types.User
	for _, u := range data.Users {
		if u.Disabled || !looksLikeServiceAccount(u) {
			continue
		}
		// PasswordLastSet == 0 means the password has never actually been
		// set through normal rotation (pwdLastSet=0) - the worst case for a
		// service account, not a safe one. It used to be silently excluded
		// by the `!u.PasswordLastSet.IsZero()` guard, so the accounts most
		// in need of flagging here were the ones this detector could never
		// see.
		if u.PasswordLastSet.IsZero() || u.PasswordLastSet.Before(threshold) {
			affected = append(affected, u)
		}
	}
	// ANSSI PA-099 (full-text source audit): the real R9 is "Identifier et
	// mener les travaux d'architecture du SI nécessaires à son
	// cloisonnement" (p.26), a project-planning recommendation, not a
	// secret-rotation rule. The closest PA-099 topic for service accounts is
	// R33 (p.50-51, "secrets réutilisables des tâches planifiées et des
	// services Windows"), which recommends least-privilege scoping and
	// Managed Service Accounts - it does not state an annual rotation
	// requirement either. This 1-year threshold is etc-collector's own
	// product benchmark.
	return wrapFinding(d, "Secrets comptes de service non rotés (>1 an, product benchmark)",
		"Service account credentials should be rotated at least annually (preferably via gMSA). Long-lived static secrets are a persistent credential-theft target. 1 year is etc-collector's own product benchmark; ANSSI PA-099 R33 (p.50-51) recommends least-privilege scoping and Managed Service Accounts for service accounts but does not itself prescribe a rotation interval.",
		types.SeverityMedium, len(affected), usersToEntities(affected, data.IncludeDetails))
}

// v3.1.21 dedup - ANSSI_R11_ADMINS_NOT_IN_PROTECTED_USERS removed (same
// adminCount=1-not-in-Protected-Users check as custom NOT_IN_PROTECTED_USERS).
// Mapping migrated.

// --- R14: RBCD (Resource-Based Constrained Delegation) sur un DC ---

type R14RBCDAuditDetector struct{ audit.BaseDetector }

func NewR14RBCDAuditDetector() *R14RBCDAuditDetector {
	return &R14RBCDAuditDetector{BaseDetector: audit.NewBaseDetector("ANSSI_R14_RBCD_AUDIT", audit.CategoryCompliance)}
}
func (d *R14RBCDAuditDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// ANSSI PA-099 (full-text source audit): the real R14 is "Détecter
	// automatiquement les potentiels incidents de sécurité" (p.31) -
	// unrelated to RBCD. RBCD is actually covered by R65 (p.90-91,
	// "Traiter les risques inhérents aux délégations Kerberos"), whose 4th
	// cumulative condition is: "la configuration de délégations contraintes
	// basées sur les ressources soit prohibée sur des services du Tier 0
	// depuis toute autre zone de confiance" - i.e. RBCD is a problem
	// specifically when its TARGET is a Tier 0 resource. Domain controllers
	// are the one Tier 0 asset always identifiable from collected data, so
	// this detector is scoped to RBCD configured on a DC rather than "any
	// RBCD anywhere" (the previous, much broader proxy). RBCD on non-DC
	// Tier 0 assets (PKI, backup, ADFS, …) is not covered here - the
	// collector has no general Tier 0 inventory to check against.
	dcDNs := make(map[string]bool, len(data.DomainControllers))
	for _, dc := range data.DomainControllers {
		dcDNs[strings.ToLower(dc.DN)] = true
	}
	var affected []types.Computer
	for _, c := range data.Computers {
		if len(c.AllowedToActOnBehalfOfOtherIdentity) == 0 {
			continue
		}
		if dcDNs[strings.ToLower(c.DN)] {
			affected = append(affected, c)
		}
	}
	entities := computersToEntities(affected, data.IncludeDetails)
	return wrapFinding(d, "ANSSI PA-099 R65 - RBCD configurée sur un contrôleur de domaine",
		"ANSSI PA-099 R65 (p.90-91) prohibits resource-based constrained delegation (msDS-AllowedToActOnBehalfOfOtherIdentity) configured on a Tier 0 service from any other trust zone. This detector checks the one Tier 0 asset class always identifiable from collected data - domain controllers; RBCD on other Tier 0 assets is not covered.",
		types.SeverityHigh, len(affected), entities)
}

// --- R15: Comptes admin hors OU Tier 0 dédiée ---

type R15TierModelViolationDetector struct{ audit.BaseDetector }

func NewR15TierModelViolationDetector() *R15TierModelViolationDetector {
	return &R15TierModelViolationDetector{BaseDetector: audit.NewBaseDetector("ANSSI_R15_TIER_MODEL_VIOLATION", audit.CategoryCompliance)}
}
func (d *R15TierModelViolationDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// ANSSI PA-099 (full-text source audit): the real R15 is "Augmenter les
	// niveaux fonctionnels des domaines et des forêts AD" (p.34) - DFL/FFL,
	// unrelated to tier isolation. The dedicated-OU requirement this
	// detector actually implements is R58 (p.73-74, "Créer une unité
	// organisationnelle réunissant les objets du Tier 0"): a Tier 0 OU near
	// the domain root containing Tier 0 objects, including a users sub-OU
	// for Tier 0 admin accounts - R8 (p.25) states the broader "cloisonner
	// l'administration de chaque Tier" principle behind it. Without session
	// logs we use a structural proxy: privileged users (AdminCount=1)
	// located outside a dedicated admin OU. R58 does not mandate a specific
	// OU name, so this remains a naming heuristic (OU=Tier0/OU=Admin).
	var count int
	for _, u := range data.Users {
		if !u.AdminCount || u.Disabled {
			continue
		}
		dn := strings.ToLower(u.DN)
		if strings.Contains(dn, "cn=users,") && !strings.Contains(dn, "ou=tier0") && !strings.Contains(dn, "ou=admin") {
			count++
		}
	}
	return wrapFinding(d, "ANSSI PA-099 R58 - Comptes admin hors OU Tier 0 dédiée",
		"ANSSI PA-099 R58 (p.73-74) requires a dedicated OU near the domain root for Tier 0 objects, including a sub-OU for Tier 0 admin accounts; R8 (p.25) states the underlying per-Tier administration segregation principle. Accounts still in the default CN=Users container break tier-aware GPO targeting.",
		types.SeverityMedium, count, nil)
}

// --- Shared helpers ---

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
// Protected Users group. Used by R11.
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

// computersToEntities is defined in r15_r19_r40_tier0.go (same package).

// privilegedAdminRIDs are the RID suffixes (relative to the domain SID) of
// Domain Admins (-512), Schema Admins (-518) and Enterprise Admins (-519).
var privilegedAdminRIDs = []string{"-512", "-518", "-519"}

// isPrivilegedAdmin reports whether u is a privileged administrator: either
// flagged by AdminSDHolder (AdminCount=1, the population most of this
// package's detectors already use), OR a member - direct or via primary
// group - of Domain/Schema/Enterprise Admins by RID, independent of
// AdminCount.
//
// AdminCount=1 alone has two known gaps: it's an "orphan" flag (stays 1
// forever after a first-and-only stint in a protected group, per PA-099
// R23's footnote 16, so it over-includes former admins) and it is stamped
// by AdminSDHolder on a timer (roughly hourly by default), so a JUST-added
// Domain Admin can have AdminCount still at 0 for up to that interval,
// under-including a real current admin. Cross-checking group SID/RID
// membership closes the under-inclusion side; groupSIDByDN resolves
// u.MemberOf (DNs only) to SIDs since AD does not add a memberOf backlink
// for a user's PRIMARY group, PrimaryGroupID is checked separately.
func isPrivilegedAdmin(u types.User, groupSIDByDN map[string]string) bool {
	if u.AdminCount {
		return true
	}
	for _, rid := range []int{512, 518, 519} {
		if u.PrimaryGroupID == rid {
			return true
		}
	}
	for _, dn := range u.MemberOf {
		sid := groupSIDByDN[strings.ToLower(dn)]
		for _, suffix := range privilegedAdminRIDs {
			if strings.HasSuffix(sid, suffix) {
				return true
			}
		}
	}
	return false
}

func init() {
	audit.MustRegister(NewR6InactiveAccountsDetector())
	audit.MustRegister(NewR7StaleAccountsNotRemovedDetector())
	audit.MustRegister(NewR8ServiceAccountsAsUsersDetector())
	audit.MustRegister(NewR9ServiceAccountSecretRotationDetector())
	audit.MustRegister(NewR14RBCDAuditDetector())
	audit.MustRegister(NewR15TierModelViolationDetector())
	_ = fmt.Sprintf // keep fmt imported for future error messages
}
