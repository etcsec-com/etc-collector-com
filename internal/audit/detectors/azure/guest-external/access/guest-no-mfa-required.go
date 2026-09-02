package access

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// NoMFARequiredDetector checks if MFA is required for guest users
type NoMFARequiredDetector struct {
	audit.BaseDetector
}

// NewNoMFARequiredDetector creates a new detector
func NewNoMFARequiredDetector() *NoMFARequiredDetector {
	return &NoMFARequiredDetector{
		BaseDetector: audit.NewBaseDetector("GUEST_NO_MFA_REQUIRED", audit.CategoryGuestExternal),
	}
}

// Detect executes the detection
func (d *NoMFARequiredDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	hasMFAPolicyForGuests := false

	// Check if any enabled CA policy targets guests and requires MFA
	for _, policy := range data.AzureConditionalAccessPolicies {
		if policy.State != "enabled" {
			continue
		}

		// Check if policy targets guests
		targetsGuests := false
		for _, user := range policy.IncludeUsers {
			if strings.Contains(strings.ToLower(user), "guest") ||
				strings.Contains(strings.ToLower(user), "external") {
				targetsGuests = true
				break
			}
		}

		// Check if policy requires MFA
		requiresMFA := false
		for _, control := range policy.GrantControls {
			if strings.Contains(strings.ToLower(control), "mfa") {
				requiresMFA = true
				break
			}
		}

		if targetsGuests && requiresMFA {
			hasMFAPolicyForGuests = true
			break
		}
	}

	count := 0
	if !hasMFAPolicyForGuests {
		count = 1
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "No MFA Required for Guest Users",
		Description: "No CA policy requires MFA for guest/external users.",
		Count:       count,
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewNoMFARequiredDetector())
}
