package security

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// UnifiedGroupNoExpiryDetector checks for Microsoft 365 groups without expiry
type UnifiedGroupNoExpiryDetector struct {
	audit.BaseDetector
}

// NewUnifiedGroupNoExpiryDetector creates a new detector
func NewUnifiedGroupNoExpiryDetector() *UnifiedGroupNoExpiryDetector {
	return &UnifiedGroupNoExpiryDetector{
		BaseDetector: audit.NewBaseDetector("AZ_GROUP_UNIFIED_NO_EXPIRY", audit.CategoryGroups),
	}
}

// Detect executes the detection
func (d *UnifiedGroupNoExpiryDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// Tenant-level advisory
	count := 1

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityLow,
		Category:    string(d.Category()),
		Title:       "Microsoft 365 Groups Without Expiry",
		Description: "M365 groups without expiration policy may accumulate unused groups over time.",
		Count:       count,
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewUnifiedGroupNoExpiryDetector())
}
