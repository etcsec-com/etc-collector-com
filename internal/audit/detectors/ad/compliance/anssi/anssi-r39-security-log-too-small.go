package anssi

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// --- Security Event log size + retention (real control: PA-099 R13, p.30) ---
//
// The detector ID below ("R39") is a legacy internal label predating the
// v3.1.14 remap to official PA-099 R-codes (see mappings.go's package doc).
// Official PA-099 R39 (p.53) is about physical access to Tier 0 secrets,
// unrelated. mappings.go already tags this detector ID against its real
// control (R13).

type R39SecurityLogSizeDetector struct{ audit.BaseDetector }

func NewR39SecurityLogSizeDetector() *R39SecurityLogSizeDetector {
	return &R39SecurityLogSizeDetector{BaseDetector: audit.NewBaseDetector("ANSSI_R39_SECURITY_LOG_TOO_SMALL", audit.CategoryCompliance)}
}
func (d *R39SecurityLogSizeDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// ANSSI R13 (p.30) doesn't fix a byte threshold; 1 GB (Windows default
	// is 20 MB) is an etc-collector product benchmark large enough to
	// survive a heavy-auth-load rollover without losing forensic evidence.
	const minSizeKB = 1048576
	enoughSize := false
	for _, p := range data.GPOPolicies {
		if p == nil || p.RegistrySettings == nil {
			continue
		}
		if p.RegistrySettings.SecurityLogMaxSizeKB == nil || *p.RegistrySettings.SecurityLogMaxSizeKB < minSizeKB {
			continue
		}
		// The previous implementation accepted a large SecurityLogMaxSizeKB
		// from ANY GPO regardless of what it's linked to - a GPO setting
		// 1 GB but linked only to, say, an OU of file servers never
		// touches the Domain Controllers whose 20 MB default this check
		// exists to catch, so the check would go silent while every DC
		// stayed at the vulnerable default. Require the GPO to actually
		// reach the DCs.
		if gpoLinkedToDCs(p.GUID, data) {
			enoughSize = true
			break
		}
	}
	count := 0
	if !enoughSize {
		count = 1
	}
	return wrapFinding(d, "Security event log < 1 GB on Domain Controllers",
		"ANSSI PA-099 R13 (p.30) requires logging and centralizing security-relevant events, which a log that rolls over in minutes under heavy auth load defeats. No GPO both sets the Security event log to at least 1 GB (etc-collector product benchmark; Windows default is 20 MB) AND is linked (enabled, not disabled) to the Domain Controllers OU or the domain root - the only scopes that reliably reach Domain Controllers.",
		types.SeverityMedium, count, nil)
}

// gpoLinkedToDCs reports whether a GPO (identified by its GUID) has an
// enabled link to the Domain Controllers OU or the domain root. Uses the
// same GUID-substring-match convention as R59Tier0OUPoliciesDetector
// (phase_d_detectors.go) against GPOLink.GPOCN/GPOGuid.
func gpoLinkedToDCs(gpoGUID string, data *audit.DetectorData) bool {
	guid := strings.ToLower(strings.Trim(gpoGUID, "{}"))
	if guid == "" {
		return false
	}
	for _, link := range data.GPOLinks {
		if !link.LinkEnabled || link.Disabled {
			continue
		}
		ref := strings.ToLower(link.GPOCN)
		if ref == "" {
			ref = strings.ToLower(link.GPOGuid)
		}
		if !strings.Contains(ref, guid) {
			continue
		}
		target := strings.ToLower(link.LinkedTo)
		if strings.Contains(target, "ou=domain controllers") || strings.HasPrefix(target, "dc=") {
			return true
		}
	}
	return false
}

func init() {
	audit.MustRegister(NewR39SecurityLogSizeDetector())
}
