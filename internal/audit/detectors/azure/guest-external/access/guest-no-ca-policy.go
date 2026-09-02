package access

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// NoCAPolicyDetector checks if any CA policy targets guest users
type NoCAPolicyDetector struct {
	audit.BaseDetector
}

// NewNoCAPolicyDetector creates a new detector
func NewNoCAPolicyDetector() *NoCAPolicyDetector {
	return &NoCAPolicyDetector{
		BaseDetector: audit.NewBaseDetector("GUEST_NO_CA_POLICY", audit.CategoryGuestExternal),
	}
}

// Detect executes the detection
func (d *NoCAPolicyDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	hasPolicyForGuests := false

	// Check if any enabled CA policy targets guests
	for _, policy := range data.AzureConditionalAccessPolicies {
		if policy.State != "enabled" {
			continue
		}

		// Check if policy targets guests
		for _, user := range policy.IncludeUsers {
			if strings.Contains(strings.ToLower(user), "guest") ||
				strings.Contains(strings.ToLower(user), "external") {
				hasPolicyForGuests = true
				break
			}
		}

		if hasPolicyForGuests {
			break
		}
	}

	count := 0
	if !hasPolicyForGuests {
		count = 1
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "No CA Policy for Guest Users",
		Description: "No CA policy specifically targets guest or external users.",
		Count:       count,
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewNoCAPolicyDetector())
}
