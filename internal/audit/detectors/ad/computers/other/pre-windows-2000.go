package other

import (
	"context"
	"regexp"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// PreWindows2000Detector checks for Windows 95/98 computers.
//
// T_075 — this used to also match "Windows NT|Windows 2000", byte-identical
// with COMPUTER_OS_OBSOLETE_NT's own pattern (computers/obsolete/obsolete-os.go):
// same condition, same object set (verified live on DC01: both matched
// exactly LEGACY-NT4-SRV$, nothing else), only the wording and severity
// differed. Narrowed to the two OS strings COMPUTER_OS_OBSOLETE_NT does not
// cover, rather than deleted outright, so an actual Windows 95/98 computer
// object (extremely rare, but not impossible as a pre-Windows-2000-compatible
// downlevel trust account) is not silently dropped from coverage (dedup.go, R4).
// See detectors/ad/dedup.go.
type PreWindows2000Detector struct {
	audit.BaseDetector
}

// NewPreWindows2000Detector creates a new detector
func NewPreWindows2000Detector() *PreWindows2000Detector {
	return &PreWindows2000Detector{
		BaseDetector: audit.NewBaseDetector("COMPUTER_PRE_WINDOWS_2000", audit.CategoryComputers),
	}
}

var preWin2000Pattern = regexp.MustCompile(`(?i)Windows 95|Windows 98`)

// Detect executes the detection
func (d *PreWindows2000Detector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.Computer

	for _, c := range data.Computers {
		if c.OperatingSystem == "" {
			continue
		}
		if preWin2000Pattern.MatchString(c.OperatingSystem) {
			affected = append(affected, c)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "Windows 95/98 Computer",
		Description: "Windows 95/98 compatible computer object. Weak security settings, potential compatibility exploits. Windows NT/2000 is reported separately by COMPUTER_OS_OBSOLETE_NT.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedComputerEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewPreWindows2000Detector())
}
