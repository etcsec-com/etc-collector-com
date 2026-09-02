package anssi

import (
	"context"
	"fmt"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// ANSSI-PA-099 R42 + R43 — Trust account and computer account password rotation.
//
//   R42 — Contrôler le renouvellement des mots de passe des comptes de trust
//   R43 — Contrôler le renouvellement des mots de passe des comptes
//         d'ordinateur sensibles (DCs notamment)
//
// Source: https://messervices.cyber.gouv.fr/documents-guides/anssi-guide-admin_securisee_si_ad_v1-0%20(3).pdf

// --- R42: Trust password not rotated ---

// trustPasswordWarnDays = ANSSI doesn't fix a number, but trust passwords
// are typically rotated automatically every 30 days by Windows. Anything
// past 365 days is suspicious (rotation broken or trust dormant).
const trustPasswordWarnDays = 365

// trustPasswordCriticalDays — past 2 years a trust password is almost
// certainly never rotated, indicating a broken trust or a manual override.
const trustPasswordCriticalDays = 730

type R42TrustPasswordOldDetector struct{ audit.BaseDetector }

func NewR42TrustPasswordOldDetector() *R42TrustPasswordOldDetector {
	return &R42TrustPasswordOldDetector{
		BaseDetector: audit.NewBaseDetector("ANSSI_R42_TRUST_PASSWORD_OLD", audit.CategoryCompliance),
	}
}

func (d *R42TrustPasswordOldDetector) Detect(_ context.Context, data *audit.DetectorData) []types.Finding {
	if len(data.Trusts) == 0 {
		return nil
	}

	now := data.Now
	var stale []types.Trust
	severity := types.SeverityMedium
	for _, t := range data.Trusts {
		// v3.1.18 — use the real pwdLastSet collected from the trustedDomain
		// object. If unreadable (LDAP perm denied / not collected), SKIP
		// rather than emit a false positive (the previous WhenCreated proxy
		// was wrong: a trust created 5 years ago with auto-rotation working
		// fine would erroneously trigger).
		ts := t.PasswordLastSet
		if ts.IsZero() {
			continue
		}
		age := now.Sub(ts).Hours() / 24
		switch {
		case age >= trustPasswordCriticalDays:
			stale = append(stale, t)
			severity = types.SeverityHigh
		case age >= trustPasswordWarnDays:
			stale = append(stale, t)
		}
	}
	if len(stale) == 0 {
		return nil
	}

	var entities []types.AffectedEntity
	if data.IncludeDetails {
		for _, t := range stale {
			entities = append(entities, types.AffectedEntity{
				Type: "trust",
				Name: t.TargetDomain,
			})
		}
	}

	return wrapFindingWithRepro(d, "ANSSI R42 — Trust password not recently rotated",
		"ANSSI R42 requires monitoring renewal of trust account passwords. "+
			fmt.Sprintf("%d trust(s) have a pwdLastSet older than %d days. ", len(stale), trustPasswordWarnDays)+
			"Windows updates inter-domain trust passwords every 30 days by default; a value past one year indicates broken automatic rotation, turning the trust account into a long-lived static credential.",
		severity, len(stale), entities,
		&types.FindingReproducibility{
			LDAPFilter: "(objectClass=trustedDomain)",
			LDAPAttrs:  []string{"name", "pwdLastSet", "trustDirection", "trustType"},
			Notes:      "Convert pwdLastSet from Windows FILETIME (100-ns ticks since 1601-01-01) to a date and check it is within the last 365 days.",
		})
}

// --- R43: DC machine account password not rotated ---

// dcPasswordWarnDays = Windows default rotation = 30 days. Anything past
// 60 days suggests a broken machine account password rotation (often a
// misconfigured GPO `DisablePasswordChange=1`).
const dcPasswordWarnDays = 60

type R43DCPasswordOldDetector struct{ audit.BaseDetector }

func NewR43DCPasswordOldDetector() *R43DCPasswordOldDetector {
	return &R43DCPasswordOldDetector{
		BaseDetector: audit.NewBaseDetector("ANSSI_R43_DC_PASSWORD_OLD", audit.CategoryCompliance),
	}
}

func (d *R43DCPasswordOldDetector) Detect(_ context.Context, data *audit.DetectorData) []types.Finding {
	dcs := data.DomainControllers
	if len(dcs) == 0 {
		return nil
	}

	threshold := data.Now.AddDate(0, 0, -dcPasswordWarnDays)
	var stale []types.Computer
	for _, c := range dcs {
		if c.PasswordLastSet.IsZero() {
			continue
		}
		if c.PasswordLastSet.Before(threshold) {
			stale = append(stale, c)
		}
	}
	if len(stale) == 0 {
		return nil
	}

	return wrapFindingWithRepro(d, "ANSSI R43 — Domain Controller machine password not rotated",
		"ANSSI R43 requires monitoring renewal of sensitive computer account passwords. "+
			fmt.Sprintf("%d/%d Domain Controller(s) have a machine password older than %d days. ", len(stale), len(dcs), dcPasswordWarnDays)+
			"Most often this indicates a misconfigured GPO disabling automatic machine account password change (Netlogon\\DisablePasswordChange=1) or a stale clone DC.",
		types.SeverityHigh, len(stale), computersToEntities(stale, data.IncludeDetails),
		&types.FindingReproducibility{
			LDAPFilter: "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))",
			LDAPAttrs:  []string{"sAMAccountName", "pwdLastSet"},
			Notes:      "DCs (SERVER_TRUST_ACCOUNT bit). Convert pwdLastSet from FILETIME and flag entries older than 60 days.",
		})
}

func init() {
	audit.MustRegister(NewR42TrustPasswordOldDetector())
	audit.MustRegister(NewR43DCPasswordOldDetector())
}
