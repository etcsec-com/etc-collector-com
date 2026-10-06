package network

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// DnssecDetector previously checked if DNSSEC is enabled on AD-integrated
// DNS zones. RETIRED: the only signal it read,
// zone.DNSSECEnabled, was derived from a misread LDAP dNSProperty propId
// (0x10 = DSPROPERTY_ZONE_NOREFRESH_INTERVAL, not
// DSPROPERTY_ZONE_SECURE_TIME), and even the correct property never
// encodes DNSSEC signing (RRSIG/DNSKEY) in the first place - see
// internal/providers/ldap/client.go GetDNSZones. No provider today
// collects real DNSSEC signing state (that lives in
// msDNS-SigningKeyDescriptor child objects under the zone, never queried).
// Per doctrine "un detecteur qui devine est pire qu'un controle absent",
// this detector no longer emits and is no longer registered. To bring it
// back: have GetDNSZones query msDNS-SigningKeyDescriptor (or the DNS
// server's actual DNSSEC zone settings) and re-enable emission + init().
type DnssecDetector struct {
	audit.BaseDetector
}

// NewDnssecDetector creates a new detector
func NewDnssecDetector() *DnssecDetector {
	return &DnssecDetector{
		BaseDetector: audit.NewBaseDetector("DNSSEC_NOT_ENABLED", audit.CategoryNetwork),
	}
}

// Detect is retired: it never emits. See the type comment above - no
// provider collects a trustworthy DNSSEC signing signal today, so this
// must not report a verdict it cannot measure.
func (d *DnssecDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	return []types.Finding{{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "DNSSEC Not Enabled",
		Description: "Retired: DNSSEC signing state is not currently collected by any provider (see type comment). This detector never fires.",
		Count:       0,
	}}
}

// No init()/MustRegister here (this detector is retired) - deliberately not
// wired into audit.DefaultRegistry. See Detect above.
