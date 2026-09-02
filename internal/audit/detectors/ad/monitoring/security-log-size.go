package monitoring

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// SecurityLogSizeDetector checks if security log size is sufficient
type SecurityLogSizeDetector struct {
	audit.BaseDetector
}

// NewSecurityLogSizeDetector creates a new detector
func NewSecurityLogSizeDetector() *SecurityLogSizeDetector {
	return &SecurityLogSizeDetector{
		BaseDetector: audit.NewBaseDetector("SECURITY_LOG_SIZE_SMALL", audit.CategoryMonitoring),
	}
}

const minimumLogSizeKB = 128 * 1024 // 128 MB minimum recommended

// Detect executes the detection
func (d *SecurityLogSizeDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "Security Log Size Too Small",
		Description: "Security event log maximum size is below recommended 128 MB, risking loss of critical audit events.",
		Count:       0,
	}

	logSize := helpers.FindRegistrySettingInt(data.GPOPolicies, func(rs *audit.RegistrySettings) *int {
		return rs.SecurityLogMaxSizeKB
	})

	if logSize != nil && *logSize < minimumLogSizeKB {
		finding.Count = 1
		finding.Details = map[string]interface{}{
			"currentSizeKB":      *logSize,
			"currentSizeMB":      *logSize / 1024,
			"recommendedMinimum": minimumLogSizeKB / 1024,
			"unit":               "MB",
			"recommendation":     "Set Security event log maximum size to at least 128 MB via Group Policy.",
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewSecurityLogSizeDetector())
}
