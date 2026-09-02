package access

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// AppAccessUnrestrictedDetector checks if guest application access is unrestricted
type AppAccessUnrestrictedDetector struct {
	audit.BaseDetector
}

// NewAppAccessUnrestrictedDetector creates a new detector
func NewAppAccessUnrestrictedDetector() *AppAccessUnrestrictedDetector {
	return &AppAccessUnrestrictedDetector{
		BaseDetector: audit.NewBaseDetector("GUEST_APP_ACCESS_UNRESTRICTED", audit.CategoryGuestExternal),
	}
}

// Detect executes the detection
func (d *AppAccessUnrestrictedDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// Tenant-level advisory
	count := 1

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "Guest Application Access Unrestricted",
		Description: "Guest users may access applications without additional restrictions.",
		Count:       count,
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewAppAccessUnrestrictedDetector())
}
