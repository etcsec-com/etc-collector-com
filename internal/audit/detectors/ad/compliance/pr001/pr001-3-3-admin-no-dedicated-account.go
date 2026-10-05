package pr001

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// --- ANSSI PA-022 R27: Comptes admin dédiés (heuristic on EmployeeID overlap) ---
//
// ANSSI PA-022 R27 ("Utiliser des comptes d'administration dédiés", p.33)
// requires every administrator to have one or more admin accounts distinct
// from their standard user account, with different authentication secrets
// per account. Heuristic: flag enabled admin users (AdminCount=1) that don't
// share an EmployeeID with another non-admin user in the same domain.
//
// What this actually measures vs. what R27 asks: EmployeeID overlap is a
// proxy for "this person also holds a distinct non-admin account" - it
// cannot observe whether the two accounts use different authentication
// secrets (R27's second sentence), and it depends entirely on EmployeeID
// being populated consistently across the domain. An admin whose EmployeeID
// is empty or unmatched is flagged, but that's equally consistent with
// "no separate account exists" (real R27 violation) and "EmployeeID just
// isn't populated for this identity" (false positive) - the detector cannot
// tell those apart from AD data alone.

type PR001AdminHasNormalAccountDetector struct{ audit.BaseDetector }

func NewPR001AdminHasNormalAccountDetector() *PR001AdminHasNormalAccountDetector {
	return &PR001AdminHasNormalAccountDetector{BaseDetector: audit.NewBaseDetector("PR001_3_3_ADMIN_NO_DEDICATED_ACCOUNT", audit.CategoryCompliance)}
}
func (d *PR001AdminHasNormalAccountDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// Build set of EmployeeIDs of NON-admin enabled accounts.
	normalEIDs := map[string]bool{}
	for _, u := range data.Users {
		if u.Disabled || u.AdminCount {
			continue
		}
		if u.EmployeeID != "" {
			normalEIDs[u.EmployeeID] = true
		}
	}
	count := 0
	for _, u := range data.Users {
		if u.Disabled || !u.AdminCount {
			continue
		}
		// Skip built-in administrator (RID 500) - it's a system account by design.
		if strings.HasSuffix(u.ObjectSID, "-500") {
			continue
		}
		// Admin without EmployeeID OR whose EmployeeID has no matching normal
		// account = no dedicated separation.
		if u.EmployeeID == "" || !normalEIDs[u.EmployeeID] {
			count++
		}
	}
	return wrapFinding(d, "PA-022 R27 - Admins sans compte nominatif standard distinct",
		"ANSSI PA-022 R27 requires every admin to have a dedicated account, separate from their daily user account. HEURISTIC, not a direct measurement: matched via EmployeeID overlap - admins whose EmployeeID isn't found on any non-admin enabled account are flagged. This cannot verify R27's 'different authentication secrets' requirement, and false positives are possible if EmployeeID is not populated organisation-wide.",
		types.SeverityMedium, count, nil)
}

func init() {
	audit.MustRegister(NewPR001AdminHasNormalAccountDetector())
}
