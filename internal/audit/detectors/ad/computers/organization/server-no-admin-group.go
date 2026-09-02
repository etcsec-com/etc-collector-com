package organization

import (
	"context"
	"regexp"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// ServerNoAdminGroupDetector detects servers without managed admin groups
type ServerNoAdminGroupDetector struct {
	audit.BaseDetector
}

// NewServerNoAdminGroupDetector creates a new detector
func NewServerNoAdminGroupDetector() *ServerNoAdminGroupDetector {
	return &ServerNoAdminGroupDetector{
		BaseDetector: audit.NewBaseDetector("SERVER_NO_ADMIN_GROUP", audit.CategoryComputers),
	}
}

var serverPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)server`),
	regexp.MustCompile(`(?i)^srv`),
	regexp.MustCompile(`(?i)^sql`),
	regexp.MustCompile(`(?i)^web`),
	regexp.MustCompile(`(?i)^app`),
	regexp.MustCompile(`(?i)^db`),
	regexp.MustCompile(`(?i)^file`),
}

// Detect executes the detection
func (d *ServerNoAdminGroupDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.Computer

	for _, c := range data.Computers {
		if !c.Enabled() {
			continue
		}

		// Check if it's a server
		isServer := false
		for _, pattern := range serverPatterns {
			if pattern.MatchString(c.SAMAccountName) {
				isServer = true
				break
			}
		}
		if !isServer && strings.Contains(strings.ToLower(c.OperatingSystem), "server") {
			isServer = true
		}

		if !isServer {
			continue
		}

		// Flag if description indicates it's unmanaged
		descLower := strings.ToLower(c.Description)
		isUnmanaged := strings.Contains(descLower, "unmanaged") ||
			strings.Contains(descLower, "legacy") ||
			strings.Contains(descLower, "deprecated")

		if isUnmanaged {
			affected = append(affected, c)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "Server Without Managed Admin Group",
		Description: "Servers identified as unmanaged or without proper administrative group documentation. Local admin access may not be properly controlled.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedComputerEntities(affected)
	}
	if len(affected) > 0 {
		finding.Details = map[string]interface{}{
			"recommendation": "Create dedicated admin groups for each server (e.g., SRV01-Admins) and document access.",
			"risks": []string{
				"Unknown administrators may have access",
				"Audit trail for admin actions may be incomplete",
				"Compliance violations for access management",
			},
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewServerNoAdminGroupDetector())
}
