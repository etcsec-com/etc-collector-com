package anssi

import (
	"context"
	"fmt"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// --- BP-039 R13: AD privileged accounts cached on workstations ---

type BP039PrivAccountsCachedDetector struct{ audit.BaseDetector }

func NewBP039PrivAccountsCachedDetector() *BP039PrivAccountsCachedDetector {
	return &BP039PrivAccountsCachedDetector{
		BaseDetector: audit.NewBaseDetector("BP039_PRIV_ACCOUNTS_CACHED", audit.CategoryCompliance),
	}
}

func (d *BP039PrivAccountsCachedDetector) Detect(_ context.Context, data *audit.DetectorData) []types.Finding {
	// CachedLogonsCount > 0 means cached credentials are kept locally. ANSSI
	// BP-039 R13 forbids caching AD privileged accounts; the strongest signal
	// is when no GPO ever sets the cache to 0. Default Windows = 10.
	cacheZeroed := false
	worstSeen := -1
	for _, p := range data.GPOPolicies {
		if p == nil || p.RegistrySettings == nil {
			continue
		}
		if p.RegistrySettings.CachedLogonsCount != nil {
			if *p.RegistrySettings.CachedLogonsCount == 0 {
				cacheZeroed = true
			}
			if *p.RegistrySettings.CachedLogonsCount > worstSeen {
				worstSeen = *p.RegistrySettings.CachedLogonsCount
			}
		}
	}
	if cacheZeroed {
		return nil // at least one GPO disables caching
	}
	// "Interactive logon: Number of previous logons to cache" is a
	// Security Option, normally authored via the Local Security Policy UI
	// and deployed through GptTmpl.inf's [Registry Values] section - not
	// through Administrative Templates/Registry.pol, which is what this
	// detector reads (CachedLogonsCount is only ever populated by
	// registrypol_parser.go). gptmpl_parser.go does not currently parse
	// CachedLogonsCount at all. Both parsers are out of scope here
	// (internal/providers/smb/); noted as a follow-up.
	// Practically: a GPO that sets this to 0 through the standard Security
	// Options channel is invisible to this detector and would still be
	// reported as a violation below - this is a known false-positive risk,
	// not a confirmed non-compliance, until GptTmpl.inf parsing is added.
	msg := "ANSSI BP-039 R13 forbids caching AD privileged accounts on workstations. "
	if worstSeen < 0 {
		msg += "No GPO sets Winlogon\\CachedLogonsCount, so the Windows default (10) applies - the last 10 interactive logons (including Tier 0 admins) are cached on disk and recoverable by an attacker with local SYSTEM."
	} else {
		msg += fmt.Sprintf("Highest CachedLogonsCount observed across GPOs is %d (recommended: 0 on workstations that may host privileged interactive logons).", worstSeen)
	}
	msg += " KNOWN LIMITATION: this setting is normally deployed as a Security Option via GptTmpl.inf, which the collector does not currently parse for this value - a GPO setting it to 0 through that standard channel would not be seen. Treat this finding as \"not verified via the standard channel\", not as confirmed non-compliance."
	return wrapFinding(d, "ANSSI BP-039 R13 - AD privileged accounts cached on workstations",
		msg, types.SeverityMedium, 1, nil)
}

func init() {
	audit.MustRegister(NewBP039PrivAccountsCachedDetector())
}
