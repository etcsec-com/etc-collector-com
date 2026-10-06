package anssi

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// --- BP-039 R6/R7: Configurable Code Integrity (CCI / WDAC) not deployed ---

type BP039CCINotDeployedDetector struct{ audit.BaseDetector }

func NewBP039CCINotDeployedDetector() *BP039CCINotDeployedDetector {
	return &BP039CCINotDeployedDetector{
		BaseDetector: audit.NewBaseDetector("BP039_CCI_NOT_DEPLOYED", audit.CategoryCompliance),
	}
}

func (d *BP039CCINotDeployedDetector) Detect(_ context.Context, data *audit.DetectorData) []types.Finding {
	// This used to check two signals. Signal 2
	// (DeviceGuardCodeIntegrityPolicyEnforcement, wired to
	// DeviceGuard\RequirePlatformSecurityFeatures) is "Select Platform
	// Security Level" from the "Turn On Virtualization Based Security" GPO -
	// part of VBS, not CCI/WDAC deployment. Any domain enabling VBS/HVCI
	// (BP-039 R5/R8, checked by bp039-vbs-off.go / bp039-hvci-off.go) would
	// set this and silence this detector even with zero CCI/WDAC policy
	// deployed - a false "compliant" on a control ANSSI BP-039 R6/R7
	// requires separately. Removed; only signal 1 remains.
	//
	// Signal 1 (ConfigCIPolicyFilePath) is the semantically correct field -
	// WDAC's "Deploy Windows Defender Application Control" GPO writes it
	// under HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard\
	// ConfigCIPolicyFilePath (confirmed via the DeviceGuard.admx policy
	// definition - valueName="ConfigCIPolicyFilePath" under the DeviceGuard
	// key, not a "CodeIntegrity" key). registrypol_parser.go currently
	// requires the registry key to contain "codeintegrity" to populate this
	// field, so it never matches that real GPO path - this field is
	// therefore never populated today. That parser is out of scope here
	// (internal/providers/smb/registrypol_parser.go);
	// noted as a needed follow-up. Until it's fixed, this
	// detector will conservatively report CCI/WDAC as undeployed on every
	// audit - a knowable overreport, not a silent false negative like the
	// removed VBS signal was.
	for _, p := range data.GPOPolicies {
		if p == nil || p.RegistrySettings == nil {
			continue
		}
		if p.RegistrySettings.DeviceGuardConfigCIPolicyFilePath != nil && *p.RegistrySettings.DeviceGuardConfigCIPolicyFilePath != "" {
			return nil
		}
	}
	return wrapFinding(d, "ANSSI BP-039 R6/R7 - Configurable Code Integrity (CCI/WDAC) not deployed",
		"ANSSI BP-039 R6 (sensitive workstations) and R7 (other workstations) recommend deploying Configurable Code Integrity / WDAC. No GPO references DeviceGuard\\ConfigCIPolicyFilePath, so kernel-mode + user-mode binaries aren't constrained to a signed allowlist. KNOWN LIMITATION: the collector's Registry.pol parser does not currently recognize the real GPO key path for this setting (out of this detector's scope to fix), so this finding fires on every audit today regardless of actual CCI/WDAC deployment - treat as \"not verified\", not as confirmed non-compliance, until the parser is corrected.",
		types.SeverityLow, 1, nil)
}

func init() {
	audit.MustRegister(NewBP039CCINotDeployedDetector())
}
