package organization

import (
	"context"
	"regexp"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// WorkstationInServerOuDetector checks for workstations in server OUs
type WorkstationInServerOuDetector struct {
	audit.BaseDetector
}

// NewWorkstationInServerOuDetector creates a new detector
func NewWorkstationInServerOuDetector() *WorkstationInServerOuDetector {
	return &WorkstationInServerOuDetector{
		BaseDetector: audit.NewBaseDetector("WORKSTATION_IN_SERVER_OU", audit.CategoryComputers),
	}
}

// Detect executes the detection.
//
// This is a product heuristic with no vendor/regulatory referential (an
// OU naming convention is a site-specific choice, not a standard) - never
// observed firing on the lab, no plant/revert confirmation exists.
// serverOuPatterns previously included a bare "ou=production" pattern,
// which matches ANY OU whose name contains "production" - including a
// perfectly legitimate "OU=Production-Workstations", causing that OU
// itself to be misclassified as a server OU and everything under it
// flagged. Narrowed to OU names that specifically denote server/datacenter
// infrastructure. Disabled computers are excluded: a decommissioned
// object's OU misplacement is not an active organizational risk.
func (d *WorkstationInServerOuDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// Patterns for server OUs ("ou=server" also matches the plural "Servers")
	serverOuPatterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)ou=server`),
		regexp.MustCompile(`(?i)ou=datacenter`),
	}

	// Patterns for workstation OS
	workstationOsPatterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)windows 10`),
		regexp.MustCompile(`(?i)windows 11`),
		regexp.MustCompile(`(?i)windows 7`),
		regexp.MustCompile(`(?i)windows 8`),
	}

	// Patterns for workstation names
	workstationNamePatterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)^ws`),
		regexp.MustCompile(`(?i)^pc`),
		regexp.MustCompile(`(?i)^laptop`),
		regexp.MustCompile(`(?i)^desktop`),
		regexp.MustCompile(`(?i)^nb`),
	}

	var affected []types.Computer

	for _, c := range data.Computers {
		if c.Disabled {
			continue
		}

		dn := c.DN

		// Check if it's in a server OU
		isInServerOU := false
		for _, pattern := range serverOuPatterns {
			if pattern.MatchString(dn) {
				isInServerOU = true
				break
			}
		}

		if !isInServerOU {
			continue
		}

		// Check if it's actually a workstation (not a server)
		os := strings.ToLower(c.OperatingSystem)
		name := c.SAMAccountName

		isWorkstation := false

		// Check by name pattern
		for _, pattern := range workstationNamePatterns {
			if pattern.MatchString(name) {
				isWorkstation = true
				break
			}
		}

		// Check by OS pattern
		if !isWorkstation && os != "" {
			for _, pattern := range workstationOsPatterns {
				if pattern.MatchString(os) {
					isWorkstation = true
					break
				}
			}
		}

		if isWorkstation {
			affected = append(affected, c)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityInfo,
		Category:    string(d.Category()),
		Title:       "Workstation in Server OU",
		Description: "Workstation computers found in server OUs. This causes incorrect GPO application and may indicate organizational issues.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedComputerEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewWorkstationInServerOuDetector())
}
