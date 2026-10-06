package gpo

import (
	"context"
	"fmt"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// CachedLogonsDetector checks if cached logons count is excessive
type CachedLogonsDetector struct {
	audit.BaseDetector
}

func NewCachedLogonsDetector() *CachedLogonsDetector {
	return &CachedLogonsDetector{
		BaseDetector: audit.NewBaseDetector("CACHED_LOGONS_EXCESSIVE", audit.CategoryGPO),
	}
}

// windowsDefaultCachedLogonsCount is what Windows caches when no GPO ever
// sets Winlogon\CachedLogonsCount: the last 10 interactive logon hashes.
// Source: Microsoft Learn, "Interactive logon: Number of previous logons to
// cache (in case domain controller is not available)" - Default values
// section (learn.microsoft.com/en-us/previous-versions/windows/it-pro/
// windows-server-2012-r2-and-2012/jj852209(v=ws.11)). Corroborated by ANSSI
// PA-099 §4.5 p.83 ("Par défaut, Windows garde en cache les condensats des
// 10 derniers mots de passe d'ouverture de session").
const windowsDefaultCachedLogonsCount = 10

// cachedLogonsThreshold: a prior version of this detector cited "ANSSI
// PA-099 R34.1" for the ">4" bar. That citation is fabricated - R34 in the
// official ANSSI-PA-099 PDF (p.51) is "Traiter les risques liés au contenu
// exécuté par les tâches planifiées et services Windows", unrelated to
// cached logons. ANSSI-PA-099 §4.5 (p.83) explicitly declines to set a
// numeric threshold for this cache, noting Microsoft's own security
// baselines don't recommend one either since the ideal size depends on the
// organization. The "4 or fewer" bar that IS an official threshold comes
// from the CIS Microsoft Windows Server Benchmark, section 2.3.7.7
// (Level 2): "Interactive logon: Number of previous logons to cache... is
// set to '4 or fewer logon(s)'".
const cachedLogonsThreshold = 4

func (d *CachedLogonsDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityLow,
		Category:    string(d.Category()),
		Title:       "Excessive Cached Logons",
		Description: "Winlogon\\CachedLogonsCount exceeds 4 (CIS Microsoft Windows Server Benchmark 2.3.7.7, Level 2; ideally 0 on Tier 0). Cached MS-CACHE-V2 hashes can be cracked offline if a workstation is stolen, exposing the most recent interactive logons.",
		Count:       0,
	}

	v := helpers.FindRegistrySettingInt(data.GPOPolicies, func(rs *audit.RegistrySettings) *int {
		return rs.CachedLogonsCount
	})

	// No GPO configuring the setting is NOT compliance: it means Windows
	// falls back to its default of 10, which is itself above the threshold -
	// the single most common and riskiest case. A prior version of
	// this detector treated v == nil as compliant, silently missing it.
	value := windowsDefaultCachedLogonsCount
	explicit := v != nil
	if explicit {
		value = *v
	}

	if value > cachedLogonsThreshold {
		finding.Count = 1
		details := map[string]interface{}{
			"currentValue":   value,
			"recommendation": "Set CachedLogonsCount to 4 or lower (ideally 0 on Tier 0) via GPO.",
		}
		if !explicit {
			details["source"] = fmt.Sprintf("no GPO sets Winlogon\\CachedLogonsCount; the Windows default (%d) applies", windowsDefaultCachedLogonsCount)
		}
		finding.Details = details
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewCachedLogonsDetector())
}
