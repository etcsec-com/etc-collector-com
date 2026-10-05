package anssi

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// ANSSI-BP-039 - Mise en œuvre des fonctionnalités de sécurité de Windows 10
// reposant sur la virtualisation (R5, R6/R7, R8, R9, R10*/R10**, R13, R14).
//
// Source: https://cyber.gouv.fr/sites/default/files/2017/11/np_securisation_windows10_securite_reposant_sur_la_virtualisation_v1.pdf
//
// All detectors in this group read GPO RegistrySettings populated by
// registrypol_parser from SYSVOL Registry.pol files. They emit a single
// Finding per detector, with Count=1 if no GPO enforces the recommendation
// domain-wide. See bp039_phase_c.go for the gpoSetsAtLeast/gpoMaxValue
// helpers shared across this group.

// --- BP-039 R5: VBS not enabled ---

type BP039VBSOffDetector struct{ audit.BaseDetector }

func NewBP039VBSOffDetector() *BP039VBSOffDetector {
	return &BP039VBSOffDetector{
		BaseDetector: audit.NewBaseDetector("BP039_VBS_OFF", audit.CategoryCompliance),
	}
}

func (d *BP039VBSOffDetector) Detect(_ context.Context, data *audit.DetectorData) []types.Finding {
	// Reuse the existing CredentialGuardEnabled field which actually maps to
	// DeviceGuard\EnableVirtualizationBasedSecurity (the VBS master switch).
	if gpoSetsAtLeast(data, func(rs *audit.RegistrySettings) *int { return rs.CredentialGuardEnabled }, 1) {
		return nil
	}
	return wrapFinding(d, "ANSSI BP-039 R5 - VBS not enabled domain-wide",
		"ANSSI BP-039 R5 recommends enabling Virtualization-Based Security (VBS) on every compatible workstation. No GPO sets DeviceGuard\\EnableVirtualizationBasedSecurity to 1, so HVCI / Credential Guard / Code Integrity isolation cannot benefit from hypervisor-enforced protections.",
		types.SeverityMedium, 1, nil)
}

func init() {
	audit.MustRegister(NewBP039VBSOffDetector())
}
