package security

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// SelfServiceUnrestrictedDetector checks for unrestricted self-service group management
type SelfServiceUnrestrictedDetector struct {
	audit.BaseDetector
}

// NewSelfServiceUnrestrictedDetector creates a new detector
func NewSelfServiceUnrestrictedDetector() *SelfServiceUnrestrictedDetector {
	return &SelfServiceUnrestrictedDetector{
		BaseDetector: audit.NewBaseDetector("AZ_GROUP_SELF_SERVICE", audit.CategoryGroups),
	}
}

// Detect executes the detection
func (d *SelfServiceUnrestrictedDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	count := 0

	// Check if group creation policy is unrestricted (empty or allows everyone)
	if data.AzureTenantConfig != nil {
		if data.AzureTenantConfig.GroupCreationPolicy == "" {
			count = 1
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "Self-Service Group Management Unrestricted",
		Description: "Users can create groups without restrictions, leading to sprawl and shadow IT.",
		Count:       count,
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewSelfServiceUnrestrictedDetector())
}
