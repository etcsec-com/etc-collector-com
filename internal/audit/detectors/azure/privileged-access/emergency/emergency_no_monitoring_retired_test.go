package emergency

import (
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
)

// TestPAEmergencyNoMonitoring_Retired proves PA_EMERGENCY_NO_MONITORING no
// longer emits an unconditional, unfalsifiable finding. Its old Detect()
// ignored ctx/data entirely and hard-coded Count:1 - Azure Monitor alert
// rules and diagnostic settings are ARM-scoped objects this collector never
// gathers via Graph or LDAP (grep confirmed: zero AlertRule/DiagnosticSetting/
// LogAnalytics/ActivityLog types anywhere in internal/providers or
// pkg/types). RED on unpatched code: emergency-no-monitoring.go's init()
// still calls audit.MustRegister, so Get() returns ok=true and this
// assertion fails.
func TestPAEmergencyNoMonitoring_Retired(t *testing.T) {
	if _, exists := audit.DefaultRegistry.Get("PA_EMERGENCY_NO_MONITORING"); exists {
		t.Fatal("PA_EMERGENCY_NO_MONITORING is still registered: monitoring/alerting configuration is not measurable from any data this collector gathers")
	}
}
