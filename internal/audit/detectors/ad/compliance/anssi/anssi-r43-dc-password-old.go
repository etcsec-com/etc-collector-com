package anssi

import (
	"context"
	"fmt"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// ANSSI-PA-099 R43 - DC machine account password not rotated.
//
// R43 - Contrôler le renouvellement des mots de passe des comptes
// d'ordinateur sensibles (DCs notamment)
//
// Source: https://messervices.cyber.gouv.fr/documents-guides/anssi-guide-admin_securisee_si_ad_v1-0%20(3).pdf

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

	return wrapFindingWithRepro(d, "ANSSI R43 - Domain Controller machine password not rotated",
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
	audit.MustRegister(NewR43DCPasswordOldDetector())
}
