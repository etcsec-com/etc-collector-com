package obsolete

import (
	"context"
	"regexp"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// ObsoleteOS2003Detector detects Windows Server 2003 computers
type ObsoleteOS2003Detector struct {
	audit.BaseDetector
}

// NewObsoleteOS2003Detector creates a new detector
func NewObsoleteOS2003Detector() *ObsoleteOS2003Detector {
	return &ObsoleteOS2003Detector{
		BaseDetector: audit.NewBaseDetector("COMPUTER_OS_OBSOLETE_2003", audit.CategoryComputers),
	}
}

// Detect executes the detection
func (d *ObsoleteOS2003Detector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	pattern := regexp.MustCompile(`(?i)Server 2003`)
	var affected []types.Computer

	for _, c := range data.Computers {
		os := strings.ToLower(c.OperatingSystem)
		if os != "" && pattern.MatchString(c.OperatingSystem) {
			affected = append(affected, c)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityCritical,
		Category:    string(d.Category()),
		Title:       "Obsolete OS: Windows Server 2003",
		Description: "Computers running Windows Server 2003, an unsupported operating system. No security patches available, making these systems highly vulnerable to exploitation.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedComputerEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewObsoleteOS2003Detector())
}
