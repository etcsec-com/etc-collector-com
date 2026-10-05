package anssi

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// --- BP-039 R14: Credential Guard without UEFI lock ---
//
// See bp039_phase_c.go for the shared gpoSetsAtLeast/gpoMaxValue helpers.

type BP039CredGuardNoUEFILockDetector struct{ audit.BaseDetector }

func NewBP039CredGuardNoUEFILockDetector() *BP039CredGuardNoUEFILockDetector {
	return &BP039CredGuardNoUEFILockDetector{
		BaseDetector: audit.NewBaseDetector("BP039_CRED_GUARD_NO_UEFI_LOCK", audit.CategoryCompliance),
	}
}

func (d *BP039CredGuardNoUEFILockDetector) Detect(_ context.Context, data *audit.DetectorData) []types.Finding {
	maxCG := gpoMaxValue(data, func(rs *audit.RegistrySettings) *int { return rs.LsaCfgFlags })
	// This was inverted. Per Microsoft's Credential Guard registry
	// documentation: 0 = disabled, 1 = enabled WITH UEFI lock, 2 = enabled
	// WITHOUT UEFI lock.
	// https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/configure
	// The old code fired at LsaCfgFlags==1 (actually the locked, compliant
	// state) and stayed silent at >=2 (actually the unlocked violation) -
	// backwards in exactly the same way as the HVCI check in
	// bp039-hvci-no-uefi-lock.go.
	if maxCG < 1 {
		return nil // not enabled, covered by R35
	}
	if maxCG == 1 {
		return nil // enabled WITH UEFI lock - R14 satisfied
	}
	return wrapFinding(d, "ANSSI BP-039 R14 - Credential Guard enabled without UEFI lock",
		"ANSSI BP-039 R14 requires Credential Guard to be activated with UEFI lock (LsaCfgFlags=1). Current GPOs set LsaCfgFlags to 2 (enabled, no lock), allowing a local admin to disable the protection from the OS at next reboot.",
		types.SeverityMedium, 1, nil)
}

func init() {
	audit.MustRegister(NewBP039CredGuardNoUEFILockDetector())
}
