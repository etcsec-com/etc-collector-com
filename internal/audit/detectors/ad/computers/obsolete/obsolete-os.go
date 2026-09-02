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

// obsoleteOSPatterns contains all obsolete OS patterns to detect
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
	audit.MustRegister(NewObsoleteOSXPDetector())
	audit.MustRegister(NewObsoleteOSVistaDetector())
	audit.MustRegister(NewObsoleteOS2003Detector())
	audit.MustRegister(NewObsoleteOS2008Detector())
	audit.MustRegister(NewObsoleteOSNTDetector())
}
