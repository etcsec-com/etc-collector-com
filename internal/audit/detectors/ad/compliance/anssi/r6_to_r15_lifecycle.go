package anssi

import (
	"context"
	"fmt"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// This file implements ANSSI PA-022 recommendations R6-R15 covering the
// account-lifecycle and privileged-access hygiene layer:
//
//   R6  — Désactivation des comptes inactifs (90j)
//   R7  — Suppression des comptes stales anciens (180j)
//   R8  — Comptes de service distincts des comptes nominatifs
//   R9  — Rotation des secrets des comptes de service
//   R10 — Désactivation de la pré-authentification uniquement sur demande documentée
//   R11 — Protection des comptes à privilèges par Protected Users
//   R12 — Restriction des droits de réplication (DCSync)
//   R13 — Proscription de la délégation non contrainte
//   R14 — Audit des RBCD (msDS-AllowedToActOnBehalfOfOtherIdentity)
//   R15 — Modèle en tiers (T0/T1/T2) — isolation des admins
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
	return wrapFinding(d, "ANSSI R6 — Comptes inactifs non désactivés",
		"ANSSI R6 recommends disabling accounts inactive for more than 90 days to reduce the attack surface.",
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
		last := u.LastLogonTimestamp
		if u.LastLogon.After(last) {
			last = u.LastLogon
		}
		// R7: un compte désactivé depuis plus de 180j devrait être supprimé
		if u.Disabled && !last.IsZero() && last.Before(threshold) {
			affected = append(affected, u)
		}
	}
	return wrapFinding(d, "ANSSI R7 — Comptes stales (180j+) non supprimés",
		"ANSSI R7 recommends deleting disabled accounts that haven't been used in 180+ days to reduce directory bloat and risk of unnoticed reactivation.",
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
	return wrapFinding(d, "ANSSI R8 — Comptes de service indistincts des comptes nominatifs",
		"ANSSI R8 requires service accounts to be clearly separated from nominative accounts (no mailbox, no HR attributes). Shared hybrids hide privilege and muddy audit trails.",
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
		if !u.PasswordLastSet.IsZero() && u.PasswordLastSet.Before(threshold) {
			affected = append(affected, u)
		}
	}
	return wrapFinding(d, "ANSSI R9 — Secrets comptes de service non rotés (>1 an)",
		"ANSSI R9 recommends rotating service account credentials at least annually (preferably via gMSA). Long-lived static secrets are a persistent credential-theft target.",
		types.SeverityMedium, len(affected), usersToEntities(affected, data.IncludeDetails))
}

// v3.1.21 dedup — ANSSI_R11_ADMINS_NOT_IN_PROTECTED_USERS removed (same
// adminCount=1-not-in-Protected-Users check as custom NOT_IN_PROTECTED_USERS).
// Mapping migrated.

// --- R14: RBCD (Resource-Based Constrained Delegation) audit ---

type R14RBCDAuditDetector struct{ audit.BaseDetector }

func NewR14RBCDAuditDetector() *R14RBCDAuditDetector {
	return &R14RBCDAuditDetector{BaseDetector: audit.NewBaseDetector("ANSSI_R14_RBCD_AUDIT", audit.CategoryCompliance)}
}
func (d *R14RBCDAuditDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// Count objects with msDS-AllowedToActOnBehalfOfOtherIdentity set to something unusual.
	var count int
	for _, c := range data.Computers {
		if len(c.AllowedToActOnBehalfOfOtherIdentity) > 0 {
			count++
		}
	}
	return wrapFinding(d, "ANSSI R14 — RBCD configuré sans audit",
		"ANSSI R14 requires explicit audit trail for every msDS-AllowedToActOnBehalfOfOtherIdentity value. Orphan RBCDs are a privilege-escalation vector.",
		types.SeverityHigh, count, nil)
}

// --- R15: Modèle en tiers (T0/T1/T2) — admins avec session sur endpoints T1/T2 ---

type R15TierModelViolationDetector struct{ audit.BaseDetector }

func NewR15TierModelViolationDetector() *R15TierModelViolationDetector {
	return &R15TierModelViolationDetector{BaseDetector: audit.NewBaseDetector("ANSSI_R15_TIER_MODEL_VIOLATION", audit.CategoryCompliance)}
}
func (d *R15TierModelViolationDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// Without session logs we use a structural proxy: privileged users
	// (AdminCount=1) located outside a dedicated admin OU. T0 admins should
	// live in OU=Tier0,OU=Admin or similar, not in CN=Users by default.
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
	return wrapFinding(d, "ANSSI R15 — Comptes admin hors OU dédiée (modèle en tiers)",
		"ANSSI R15 enforces tier isolation: privileged accounts should live in dedicated OUs (e.g. OU=Tier0) with their own GPOs and ACLs, not in the default CN=Users container. Accounts in CN=Users break tier-aware GPO targeting.",
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
// query that produced the finding. v3.1.19 — used by R15/R19/R40/R42/R43/R69
// (LDAP-only detectors with clean reproduction paths).
func wrapFindingWithRepro(d audit.Detector, title, description string, sev types.Severity, count int, entities []types.AffectedEntity, repro *types.FindingReproducibility) []types.Finding {
	out := wrapFinding(d, title, description, sev, count, entities)
	if len(out) > 0 && repro != nil {
		out[0].Reproducibility = repro
	}
	return out
}

// looksLikeServiceAccount is a heuristic — ANSSI doesn't define a strict
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

func init() {
	audit.MustRegister(NewR6InactiveAccountsDetector())
	audit.MustRegister(NewR7StaleAccountsNotRemovedDetector())
	audit.MustRegister(NewR8ServiceAccountsAsUsersDetector())
	audit.MustRegister(NewR9ServiceAccountSecretRotationDetector())
	audit.MustRegister(NewR14RBCDAuditDetector())
	audit.MustRegister(NewR15TierModelViolationDetector())
	_ = fmt.Sprintf // keep fmt imported for future error messages
}
