package obsolete

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// ObsoleteOS2008Detector detects Windows Server 2008 computers (not R2)
type ObsoleteOS2008Detector struct {
	audit.BaseDetector
}

// NewObsoleteOS2008Detector creates a new detector
func NewObsoleteOS2008Detector() *ObsoleteOS2008Detector {
	return &ObsoleteOS2008Detector{
		BaseDetector: audit.NewBaseDetector("COMPUTER_OS_OBSOLETE_2008", audit.CategoryComputers),
	}
}

// Detect executes the detection
func (d *ObsoleteOS2008Detector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// Match Server 2008 but not Server 2008 R2
	var affected []types.Computer

	for _, c := range data.Computers {
		osLower := strings.ToLower(c.OperatingSystem)
		// Check for Server 2008 but exclude R2
		if osLower != "" && strings.Contains(osLower, "server 2008") && !strings.Contains(osLower, "r2") {
			affected = append(affected, c)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "Obsolete OS: Windows Server 2008",
		Description: "Computers running Windows Server 2008, an unsupported operating system. No security patches available, making these systems highly vulnerable to exploitation.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedComputerEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewObsoleteOS2008Detector())
}
