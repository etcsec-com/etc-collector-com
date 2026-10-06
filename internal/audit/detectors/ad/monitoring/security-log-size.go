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

// CIS Microsoft Windows Server Benchmark requires the Security log's maximum
// size to be at least 196608 KB (192 MB).
const minimumLogSizeKB = 196608

// Detect executes the detection
func (d *SecurityLogSizeDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "Security Log Size Too Small",
		Description: "Security event log maximum size is below the CIS-recommended 192 MB, risking loss of critical audit events.",
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
			"recommendation":     "Set Security event log maximum size to at least 192 MB via Group Policy.",
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewSecurityLogSizeDetector())
}
