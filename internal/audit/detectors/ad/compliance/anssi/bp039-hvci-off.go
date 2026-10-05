package anssi

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// --- BP-039 R8: HVCI not enabled ---
//
// See bp039_phase_c.go for the shared gpoSetsAtLeast/gpoMaxValue helpers.

type BP039HVCIOffDetector struct{ audit.BaseDetector }

func NewBP039HVCIOffDetector() *BP039HVCIOffDetector {
	return &BP039HVCIOffDetector{
		BaseDetector: audit.NewBaseDetector("BP039_HVCI_OFF", audit.CategoryCompliance),
	}
}

func (d *BP039HVCIOffDetector) Detect(_ context.Context, data *audit.DetectorData) []types.Finding {
	if gpoSetsAtLeast(data, func(rs *audit.RegistrySettings) *int { return rs.HVCIEnabled }, 1) {
		return nil
	}
	return wrapFinding(d, "ANSSI BP-039 R8 - HVCI not enabled",
		"ANSSI BP-039 R8 recommends enabling Hypervisor-Enforced Code Integrity (HVCI) on every compatible workstation. No GPO sets DeviceGuard\\HypervisorEnforcedCodeIntegrity, so kernel-mode integrity verification doesn't run inside the secure VBS partition.",
		types.SeverityMedium, 1, nil)
}

func init() {
	audit.MustRegister(NewBP039HVCIOffDetector())
}
