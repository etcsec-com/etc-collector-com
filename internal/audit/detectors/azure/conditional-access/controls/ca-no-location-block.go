package controls

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// NoLocationBlockDetector checks if any CA policy uses location-based blocking
type NoLocationBlockDetector struct {
	audit.BaseDetector
}

// NewNoLocationBlockDetector creates a new detector
func NewNoLocationBlockDetector() *NoLocationBlockDetector {
	return &NoLocationBlockDetector{
		BaseDetector: audit.NewBaseDetector("CA_NO_LOCATION_BLOCK", audit.CategoryConditionalAccess),
	}
}

// Detect executes the detection
//
// Source: Microsoft Learn, "Conditional Access: Block access by location"
// (learn.microsoft.com/en-us/entra/identity/conditional-access/
// policy-block-example) - a location-based blocking policy is built by
// pairing a locations condition with the "Block access" grant control. The
// title and description here promise "blocking"; before this fix, any
// enabled policy with a locations condition satisfied the check regardless
// of its grant control, so a policy that only required MFA when a location
// condition matched (not blocking) silenced this detector even though
// nothing was actually being blocked by location.
func (d *NoLocationBlockDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	hasLocationBlockPolicy := false

	for _, p := range data.AzureConditionalAccessPolicies {
		if p.State != "enabled" || len(p.IncludeLocations) == 0 {
			continue
		}
		for _, control := range p.GrantControls {
			if control == "block" {
				hasLocationBlockPolicy = true
				break
			}
		}
		if hasLocationBlockPolicy {
			break
		}
	}

	count := 0
	if !hasLocationBlockPolicy {
		count = 1
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "No Location-Based Access Blocking",
		Description: "No CA policy uses location conditions to block access from untrusted locations.",
		Count:       count,
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewNoLocationBlockDetector())
}
