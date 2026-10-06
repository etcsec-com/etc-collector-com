package anssi

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// --- R7: Comptes stales > 180j non supprimés ---
//
// See r6_to_r15_lifecycle.go for the wrapFinding/usersToEntities helpers
// shared across this detector group.

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

func init() {
	audit.MustRegister(NewR7StaleAccountsNotRemovedDetector())
}
