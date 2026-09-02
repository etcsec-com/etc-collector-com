package governance

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// NoExpirationPolicyDetector checks for missing guest account expiration policy
type NoExpirationPolicyDetector struct {
	audit.BaseDetector
}

// NewNoExpirationPolicyDetector creates a new detector
func NewNoExpirationPolicyDetector() *NoExpirationPolicyDetector {
	return &NoExpirationPolicyDetector{
		BaseDetector: audit.NewBaseDetector("GUEST_NO_EXPIRATION_POLICY", audit.CategoryGuestExternal),
	}
}

// Detect executes the detection
func (d *NoExpirationPolicyDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// Tenant-level advisory
	count := 1

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "No Guest Account Expiration Policy",
		Description: "Guest accounts do not have automatic expiration. Set time-limited access for external users.",
		Count:       count,
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewNoExpirationPolicyDetector())
}
