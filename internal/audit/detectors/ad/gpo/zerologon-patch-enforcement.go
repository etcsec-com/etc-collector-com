package gpo

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// ZerologonDetector checks if Zerologon enforcement is enabled
type ZerologonDetector struct {
	audit.BaseDetector
}

func NewZerologonDetector() *ZerologonDetector {
	return &ZerologonDetector{
		BaseDetector: audit.NewBaseDetector("ZEROLOGON_PATCH_ENFORCEMENT", audit.CategoryGPO),
	}
}

// Honest re-scope (Microsoft KB4557222, "How to manage the changes in
// Netlogon secure channel connections associated with CVE-2020-1472"):
// FullSecureChannelProtection was a Netlogon\Parameters registry value
// introduced with the August 11, 2020 "Initial Deployment Phase" update,
// letting administrators opt IN to enforcement early (default 0 = still
// allow vulnerable connections from non-Windows devices) ahead of the
// mandatory "Enforcement Phase". Microsoft's own guidance is explicit about
// what happened next: "Deploying updates released February 9, 2021 or later
// will turn on DC enforcement mode" - unconditionally, on every DC that has
// that update installed, regardless of FullSecureChannelProtection - and
// "you will not be able to disable enforcement mode." At that point,
// "the FullSecureChannelProtection registry key is no longer needed and
// will no longer be supported."
//
// So on any DC carrying the February 2021 or later cumulative update (which
// is every supported, patched DC today), this registry value is inert: it
// no longer controls, and no longer indicates, whether Netlogon secure
// channel enforcement is active - enforcement is on regardless of what this
// key says. Reading it therefore cannot tell us whether a DC is actually
// Zerologon-protected; it can only ever surface a leftover, pre-2021
// opt-in registry value with no bearing on current risk. The collector has
// no already-collected signal for actual OS build/patch level on DCs
// (types.Computer only carries OperatingSystem/OperatingSystemVersion, the
// OS edition string and major version - not KB/patch level), so this check
// is re-scoped to what it can honestly claim: legacy registry hygiene, not
// a live Zerologon vulnerability indicator. Severity is lowered accordingly
// (was Critical, framed as if this directly meant "allowing complete domain
// takeover").
func (d *ZerologonDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityLow,
		Category:    string(d.Category()),
		Title:       "Legacy Zerologon (CVE-2020-1472) Enforcement Registry Value Not Set",
		Description: "The Netlogon\\Parameters\\FullSecureChannelProtection registry value is not set to 1 via GPO. This value only mattered during the transitional window between Microsoft's August 2020 Initial Deployment Phase update and the February 9, 2021 Enforcement Phase; since then, every DC with the February 2021 or later update installed enforces the Netlogon secure channel protection unconditionally, and Microsoft has stated this registry key 'is no longer needed and will no longer be supported'. This check does NOT measure actual DC patch level or actual Zerologon exposure - it only flags a leftover pre-2021 opt-in setting, which is expected to be unset on a modern, patched estate and does not by itself indicate vulnerability.",
		Count:       0,
	}

	v := helpers.FindRegistrySettingInt(data.GPOPolicies, func(rs *audit.RegistrySettings) *int {
		return rs.ZerologonEnforcement
	})

	if v == nil || *v != 1 {
		finding.Count = 1
		finding.Details = map[string]interface{}{
			"recommendation": "This is a legacy hygiene check, not a patch-level or vulnerability assessment. Confirm all Domain Controllers have the February 2021 or later cumulative update installed (mandatory Netlogon secure channel enforcement) via your patch management tooling - this registry value cannot tell you that.",
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewZerologonDetector())
}
