package anssi

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// --- R9: Secrets des comptes de service non rotés (>1 an) ---
//
// See r6_to_r15_lifecycle.go for the wrapFinding/usersToEntities/
// looksLikeServiceAccount helpers shared across this detector group.

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

func init() {
	audit.MustRegister(NewR9ServiceAccountSecretRotationDetector())
}
