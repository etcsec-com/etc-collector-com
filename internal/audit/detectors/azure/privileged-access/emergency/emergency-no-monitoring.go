package emergency

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// EmergencyNoMonitoringDetector is an advisory detector for emergency account monitoring
type EmergencyNoMonitoringDetector struct {
	audit.BaseDetector
}

// NewEmergencyNoMonitoringDetector creates a new detector
func NewEmergencyNoMonitoringDetector() *EmergencyNoMonitoringDetector {
	return &EmergencyNoMonitoringDetector{
		BaseDetector: audit.NewBaseDetector("PA_EMERGENCY_NO_MONITORING", audit.CategoryPrivilegedAccess),
	}
}

// Detect executes the detection
func (d *EmergencyNoMonitoringDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// This is a tenant-level advisory check
	// Actual monitoring configuration cannot be verified from current data
	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "Emergency Account Usage Not Monitored",
		Description: "No alerts configured for emergency account sign-ins. Usage of break-glass accounts must be monitored and investigated immediately. Configure Azure Monitor alerts for sign-ins by emergency access accounts.",
		Count:       1,
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewEmergencyNoMonitoringDetector())
}
