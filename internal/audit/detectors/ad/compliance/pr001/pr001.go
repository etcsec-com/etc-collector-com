// Package pr001 implements two AD-observable administration hygiene checks.
//
// the package (and both detectors below) previously cited a guide
// "ANSSI PR-001" with numbered sections ("§3.3", "§5.1"). No such ANSSI
// guide exists. The real sources, verified against the published PDFs:
// - dedicated admin accounts: ANSSI-PA-022 v3.0 (11/05/2021) R27
// "Utiliser des comptes d'administration dédiés", p.33 - a DIFFERENT,
// older, non-AD-specific guide from the PA-099 AD guide used elsewhere
// in this package.
// - DC OS obsolescence: ANSSI-PA-099 v1.0 (02/10/2023) R16 "Procéder aux
// montées de versions Windows des systèmes du Tier 0", p.34 (previously
// cited as p.35 - R16's own recommendation text is on p.34; the "Attention"
// advisory box that follows it spills onto p.35, but R16 itself is not).
//
// The package name "pr001" is legacy from the fabricated citation; kept
// as-is because it's also the detector IDs' registered key in
// internal/audit/compliance/mappings.go (out of scope here -
// renaming needs to happen there too).
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

// --- ANSSI PA-099 R16: DC OS obsolete ---

type PR001DCOSObsoleteDetector struct{ audit.BaseDetector }

func NewPR001DCOSObsoleteDetector() *PR001DCOSObsoleteDetector {
	return &PR001DCOSObsoleteDetector{BaseDetector: audit.NewBaseDetector("PR001_5_1_DC_OS_OBSOLETE", audit.CategoryCompliance)}
}
func (d *PR001DCOSObsoleteDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// DCs running anything older than Windows Server 2019 (NT 10.0 build
	// 17763+) are obsolete in practice (mainstream support ended).
	//
	// Two fixes to the substring list and its justification.
	//  1. "2000" was missing - a Windows 2000 Server DC (the oldest AD-
	//     capable OS, end-of-life since 2010) passed through unflagged.
	//  2. 2016 was lumped in with 2003/2008/2012 under "security patches
	//     limited or non-existent" - factually wrong for 2016: mainstream
	//     support ended January 11, 2022, but Windows Server 2016 continues
	//     to receive regular (non-ESU, no additional cost) security updates
	//     under Extended Support until January 12, 2027. The flag itself is
	//     still defensible under R16 (which asks for staying on recent,
	//     actively-developed versions, not merely "not yet fully dead"), but
	//     the justification text must not claim its patches are
	//     non-existent when they aren't. Reworded to distinguish fully
	//     end-of-support versions from 2016's Extended Support state.
	count := 0
	for _, dc := range data.DomainControllers {
		os := strings.ToLower(dc.OperatingSystem)
		if os == "" {
			continue
		}
		// Match on common identifiable substrings.
		if strings.Contains(os, "2000") || strings.Contains(os, "2003") || strings.Contains(os, "2008") || strings.Contains(os, "2012") || strings.Contains(os, "2016") {
			count++
		}
	}
	return wrapFinding(d, "PA-099 R16 - Domain Controller sur OS obsolète",
		"ANSSI PA-099 R16 requires domain controller operating systems to be kept regularly up to date, moving to recent stable Windows Server versions. Windows Server 2000/2003/2008/2012 are fully out of support (no security patches at all, outside paid custom agreements). Windows Server 2016 is past mainstream support (ended January 2022) and, while it still receives free security updates under Extended Support until January 2027, no longer receives feature updates or the fastest security response - R16 asks for staying current, not merely avoiding full end-of-support.",
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
