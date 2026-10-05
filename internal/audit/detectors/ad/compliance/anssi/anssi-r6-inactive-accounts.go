package anssi

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// This detector implements part of etc-collector's account-lifecycle and
// privileged-access hygiene layer for AD. Despite its "R6" ID (kept for
// history), it does NOT correspond to ANSSI PA-099's real R6: a full-text
// audit of PA-099 found R6 covers attack-path analysis (p.21-22), unrelated
// to inactivity. See the comment below for the real PA-099 content at that
// number. Where a genuine ANSSI source exists for what a detector measures,
// it is cited precisely (guide, recommendation, page); where none exists,
// the finding is described as a product benchmark, not an ANSSI requirement.
//
// See r6_to_r15_lifecycle.go for the wrapFinding/usersToEntities helpers
// shared across this detector group.

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

func init() {
	audit.MustRegister(NewR6InactiveAccountsDetector())
}
