package anssi

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// --- BP-039 R9: HVCI without UEFI lock ---
//
// See bp039_phase_c.go for the shared gpoSetsAtLeast/gpoMaxValue helpers.

type BP039HVCINoUEFILockDetector struct{ audit.BaseDetector }

func NewBP039HVCINoUEFILockDetector() *BP039HVCINoUEFILockDetector {
	return &BP039HVCINoUEFILockDetector{
		BaseDetector: audit.NewBaseDetector("BP039_HVCI_NO_UEFI_LOCK", audit.CategoryCompliance),
	}
}

func (d *BP039HVCINoUEFILockDetector) Detect(_ context.Context, data *audit.DetectorData) []types.Finding {
	maxHVCI := gpoMaxValue(data, func(rs *audit.RegistrySettings) *int { return rs.HVCIEnabled })
	// This was inverted. Per Microsoft's HypervisorEnforcedCodeIntegrity
	// registry documentation (same convention as LsaCfgFlags in
	// bp039-cred-guard-no-uefi-lock.go): 0 = disabled, 1 = enabled WITH UEFI
	// lock, 2 = enabled WITHOUT UEFI lock.
	// https://learn.microsoft.com/en-us/windows/security/hardware-security/enable-virtualization-based-protection-of-code-integrity
	// The old code fired when maxHVCI==1 (actually the locked, compliant
	// state) and stayed silent at maxHVCI>=2 (actually the unlocked
	// violation) - a false positive on a compliant fleet and a false
	// negative on the exact violation ANSSI BP-039 R9 targets.
	if maxHVCI < 1 {
		return nil // covered by R8 instead
	}
	if maxHVCI == 1 {
		return nil // enabled WITH UEFI lock - R9 satisfied
	}
	return wrapFinding(d, "ANSSI BP-039 R9 - HVCI enabled without UEFI lock",
		"ANSSI BP-039 R9 requires HVCI to be deployed with UEFI lock. Current GPOs enable HVCI without UEFI lock (HypervisorEnforcedCodeIntegrity=2), so a local administrator can disable HVCI from the OS without UEFI access.",
		types.SeverityLow, 1, nil)
}

func init() {
	audit.MustRegister(NewBP039HVCINoUEFILockDetector())
}
