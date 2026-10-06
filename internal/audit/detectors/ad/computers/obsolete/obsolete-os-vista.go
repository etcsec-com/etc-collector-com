package obsolete

import (
	"context"
	"regexp"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// ObsoleteOSVistaDetector detects Windows Vista computers
type ObsoleteOSVistaDetector struct {
	audit.BaseDetector
}

// NewObsoleteOSVistaDetector creates a new detector
func NewObsoleteOSVistaDetector() *ObsoleteOSVistaDetector {
	return &ObsoleteOSVistaDetector{
		BaseDetector: audit.NewBaseDetector("COMPUTER_OS_OBSOLETE_VISTA", audit.CategoryComputers),
	}
}

// Detect executes the detection
func (d *ObsoleteOSVistaDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	pattern := regexp.MustCompile(`(?i)Windows Vista`)
	var affected []types.Computer

	for _, c := range data.Computers {
		os := strings.ToLower(c.OperatingSystem)
		if os != "" && pattern.MatchString(c.OperatingSystem) {
			affected = append(affected, c)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "Obsolete OS: Windows Vista",
		Description: "Computers running Windows Vista, an unsupported operating system. No security patches available, making these systems highly vulnerable to exploitation.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedComputerEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewObsoleteOSVistaDetector())
}
