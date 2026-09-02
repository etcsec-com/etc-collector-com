package pim

import (
	"context"
	"regexp"
	"strconv"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// PIMLongActivationDetector detects PIM-eligible roles with long activation duration
type PIMLongActivationDetector struct {
	audit.BaseDetector
}

// NewPIMLongActivationDetector creates a new detector
func NewPIMLongActivationDetector() *PIMLongActivationDetector {
	return &PIMLongActivationDetector{
		BaseDetector: audit.NewBaseDetector("PA_PIM_LONG_ACTIVATION", audit.CategoryPrivilegedAccess),
	}
}

// parseISO8601Duration parses ISO 8601 duration (e.g., "PT8H", "PT12H30M") and returns hours
func parseISO8601Duration(duration string) int {
	if duration == "" {
		return 0
	}

	// Match PT{hours}H or PT{hours}H{minutes}M patterns
	hourPattern := regexp.MustCompile(`PT(\d+)H`)
	matches := hourPattern.FindStringSubmatch(duration)

	if len(matches) > 1 {
		hours, err := strconv.Atoi(matches[1])
		if err == nil {
			return hours
		}
	}

	return 0
}

// Detect executes the detection
func (d *PIMLongActivationDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.RoleAssignment

	const maxRecommendedHours = 8

	for _, ra := range data.AzureRoleAssignments {
		if !ra.IsEligible {
			continue
		}

		hours := parseISO8601Duration(ra.ActivationDuration)
		if hours > maxRecommendedHours {
			affected = append(affected, ra)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "Long PIM Activation Duration",
		Description: "PIM role activations allow durations longer than 8 hours. Shorter activation periods limit exposure window if credentials are compromised.",
		Count:       len(affected),
		Details: map[string]interface{}{
			"recommendation": "Configure maximum activation duration to 4-8 hours for privileged roles",
			"threshold":      "8 hours",
		},
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.RoleAssignmentsToAffectedEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewPIMLongActivationDetector())
}
