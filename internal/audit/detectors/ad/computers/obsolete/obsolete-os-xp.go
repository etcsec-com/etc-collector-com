package obsolete

import (
	"context"
	"regexp"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// ObsoleteOSPattern defines a pattern for obsolete OS detection
type ObsoleteOSPattern struct {
	Pattern  *regexp.Regexp
	TypeID   string
	Severity types.Severity
	OSName   string
}

// obsoleteOSPatterns is not currently read by any detector in this package -
// each Detect() below compiles and matches its own pattern inline instead.
var obsoleteOSPatterns = []ObsoleteOSPattern{
	{
		Pattern:  regexp.MustCompile(`(?i)Windows XP`),
		TypeID:   "COMPUTER_OS_OBSOLETE_XP",
		Severity: types.SeverityCritical,
		OSName:   "Windows XP",
	},
	{
		Pattern:  regexp.MustCompile(`(?i)Server 2003`),
		TypeID:   "COMPUTER_OS_OBSOLETE_2003",
		Severity: types.SeverityCritical,
		OSName:   "Windows Server 2003",
	},
	{
		Pattern:  regexp.MustCompile(`(?i)Server 2008`), // 2008 detection - R2 exclusion handled in code
		TypeID:   "COMPUTER_OS_OBSOLETE_2008",
		Severity: types.SeverityHigh,
		OSName:   "Windows Server 2008",
	},
	{
		Pattern:  regexp.MustCompile(`(?i)Windows Vista`),
		TypeID:   "COMPUTER_OS_OBSOLETE_VISTA",
		Severity: types.SeverityHigh,
		OSName:   "Windows Vista",
	},
}

// ObsoleteOSXPDetector detects Windows XP computers
type ObsoleteOSXPDetector struct {
	audit.BaseDetector
}

// NewObsoleteOSXPDetector creates a new detector
func NewObsoleteOSXPDetector() *ObsoleteOSXPDetector {
	return &ObsoleteOSXPDetector{
		BaseDetector: audit.NewBaseDetector("COMPUTER_OS_OBSOLETE_XP", audit.CategoryComputers),
	}
}

// Detect executes the detection
func (d *ObsoleteOSXPDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	pattern := regexp.MustCompile(`(?i)Windows XP`)
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
		Title:       "Obsolete OS: Windows XP",
		Description: "Computers running Windows XP, an unsupported operating system. No security patches available, making these systems highly vulnerable to exploitation.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedComputerEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewObsoleteOSXPDetector())
}
