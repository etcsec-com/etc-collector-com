package anssi

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// --- R8: Comptes de service utilisés comme comptes nominatifs ---
//
// See r6_to_r15_lifecycle.go for the wrapFinding/usersToEntities/
// looksLikeServiceAccount helpers shared across this detector group.

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

func init() {
	audit.MustRegister(NewR8ServiceAccountsAsUsersDetector())
}
