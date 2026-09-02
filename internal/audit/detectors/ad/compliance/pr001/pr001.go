// Package pr001 implements detectors specific to ANSSI PR-001 (Recommandations
// relatives à l'administration sécurisée des systèmes d'information). Most
// PR-001 recommendations are operational and not technically observable from
// AD; this file covers the few that are.
package pr001

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// --- PR-001 §3.3: Comptes admin dédiés (heuristic on EmployeeID overlap) ---
//
// PR-001 §3.3 mandates that every administrator have a separate admin account
// distinct from their standard daily account. Heuristic: flag enabled admin
// users (AdminCount=1) that share an EmployeeID with another non-admin user
// in the same domain (= same human, two accounts done right) → these PASS.
// Flag admin users that don't share any EmployeeID → likely the admin uses
// their primary account for elevation, which violates PR-001 §3.3.

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
		// Skip built-in administrator (RID 500) — it's a system account by design.
		if strings.HasSuffix(u.ObjectSID, "-500") {
			continue
		}
		// Admin without EmployeeID OR whose EmployeeID has no matching normal
		// account = no dedicated separation.
		if u.EmployeeID == "" || !normalEIDs[u.EmployeeID] {
			count++
		}
	}
	return wrapFinding(d, "PR-001 §3.3 — Admins sans compte nominatif standard distinct",
		"ANSSI PR-001 §3.3 requires every admin to have a separate daily account. HEURISTIC: matched via EmployeeID — admins whose EmployeeID isn't found on any non-admin enabled account are flagged. False positives possible if EmployeeID is not populated organisation-wide.",
		types.SeverityMedium, count, nil)
}

// --- PR-001 §5.1: DC OS obsolete ---

type PR001DCOSObsoleteDetector struct{ audit.BaseDetector }

func NewPR001DCOSObsoleteDetector() *PR001DCOSObsoleteDetector {
	return &PR001DCOSObsoleteDetector{BaseDetector: audit.NewBaseDetector("PR001_5_1_DC_OS_OBSOLETE", audit.CategoryCompliance)}
}
func (d *PR001DCOSObsoleteDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// DCs running anything older than Windows Server 2019 (NT 10.0 build
	// 17763+) are obsolete in practice (mainstream support ended).
	count := 0
	for _, dc := range data.DomainControllers {
		os := strings.ToLower(dc.OperatingSystem)
		if os == "" {
			continue
		}
		// Match on common identifiable substrings.
		if strings.Contains(os, "2003") || strings.Contains(os, "2008") || strings.Contains(os, "2012") || strings.Contains(os, "2016") {
			count++
		}
	}
	return wrapFinding(d, "PR-001 §5.1 — Domain Controller sur OS obsolète",
		"ANSSI PR-001 §5.1 requires DCs to run a supported OS. Windows Server 2003/2008/2012/2016 are out of mainstream support — security patches limited or non-existent.",
		types.SeverityHigh, count, nil)
}

// --- shared ---

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

func init() {
	audit.MustRegister(NewPR001AdminHasNormalAccountDetector())
	audit.MustRegister(NewPR001DCOSObsoleteDetector())
}
