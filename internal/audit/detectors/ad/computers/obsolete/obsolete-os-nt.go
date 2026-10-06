package obsolete

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// ObsoleteOSNTDetector detects Windows NT 4.0 computers
type ObsoleteOSNTDetector struct {
	audit.BaseDetector
}

// NewObsoleteOSNTDetector creates a new detector
func NewObsoleteOSNTDetector() *ObsoleteOSNTDetector {
	return &ObsoleteOSNTDetector{
		BaseDetector: audit.NewBaseDetector("COMPUTER_OS_OBSOLETE_NT", audit.CategoryComputers),
	}
}

// Detect executes the detection
func (d *ObsoleteOSNTDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.Computer

	for _, c := range data.Computers {
		osLower := strings.ToLower(c.OperatingSystem)
		if osLower != "" && (strings.Contains(osLower, "windows nt") || strings.Contains(osLower, "windows 2000")) {
			affected = append(affected, c)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityCritical,
		Category:    string(d.Category()),
		Title:       "Obsolete OS: Windows NT/2000",
		Description: "Computers running Windows NT 4.0 or Windows 2000, extremely outdated and unsupported operating systems. These systems lack all modern security features and are trivially exploitable.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedComputerEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewObsoleteOSNTDetector())
}
