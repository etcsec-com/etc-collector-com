package pr001

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

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

func init() {
	audit.MustRegister(NewPR001DCOSObsoleteDetector())
}
