package policies

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// NoDeviceComplianceDetector checks if any CA policy requires device compliance
type NoDeviceComplianceDetector struct {
	audit.BaseDetector
}

// NewNoDeviceComplianceDetector creates a new detector
func NewNoDeviceComplianceDetector() *NoDeviceComplianceDetector {
	return &NoDeviceComplianceDetector{
		BaseDetector: audit.NewBaseDetector("CA_NO_DEVICE_COMPLIANCE", audit.CategoryConditionalAccess),
	}
}

// Detect executes the detection
func (d *NoDeviceComplianceDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	hasDeviceCompliancePolicy := false

	for _, p := range data.AzureConditionalAccessPolicies {
		if p.State != "enabled" {
			continue
		}

		if containsStr(p.GrantControls, "compliantDevice") || containsStr(p.GrantControls, "domainJoinedDevice") {
			hasDeviceCompliancePolicy = true
			break
		}
	}

	count := 0
	if !hasDeviceCompliancePolicy {
		count = 1
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "No CA Policy Requires Device Compliance",
		Description: "No CA policy requires compliant or domain-joined devices.",
		Count:       count,
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewNoDeviceComplianceDetector())
}
