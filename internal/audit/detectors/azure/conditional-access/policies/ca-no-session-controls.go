package policies

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// NoSessionControlsDetector checks if any CA policy uses session controls
type NoSessionControlsDetector struct {
	audit.BaseDetector
}

// NewNoSessionControlsDetector creates a new detector
func NewNoSessionControlsDetector() *NoSessionControlsDetector {
	return &NoSessionControlsDetector{
		BaseDetector: audit.NewBaseDetector("CA_NO_SESSION_CONTROLS", audit.CategoryConditionalAccess),
	}
}

// Detect executes the detection
func (d *NoSessionControlsDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	hasSessionControls := false

	for _, p := range data.AzureConditionalAccessPolicies {
		if p.State != "enabled" {
			continue
		}

		if p.SignInFrequencyValue > 0 || p.PersistentBrowserMode != "" {
			hasSessionControls = true
			break
		}
	}

	count := 0
	if !hasSessionControls {
		count = 1
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "No CA Policy with Session Controls",
		Description: "No CA policy configures session controls (sign-in frequency, persistent browser).",
		Count:       count,
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewNoSessionControlsDetector())
}
