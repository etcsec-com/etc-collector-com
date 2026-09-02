package network

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// DnssecDetector checks if DNSSEC is not enabled
type DnssecDetector struct {
	audit.BaseDetector
}

// NewDnssecDetector creates a new detector
func NewDnssecDetector() *DnssecDetector {
	return &DnssecDetector{
		BaseDetector: audit.NewBaseDetector("DNSSEC_NOT_ENABLED", audit.CategoryNetwork),
	}
}

// Detect executes the detection
func (d *DnssecDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "DNSSEC Not Enabled",
		Description: "DNSSEC is not enabled for the domain. DNS responses can be spoofed, enabling cache poisoning and MITM attacks.",
		Count:       0,
	}

	if len(data.DNSZones) == 0 {
		// No DNS zone data collected — nothing measured, nothing reported.
		// The previous behaviour reported this as a finding, the same
		// "absence of measurement = negative finding" bug T_046/B_049 fixed
		// on SMB_SIGNING_DISABLED (dns-dynamic-update.go and dns-wildcard.go,
		// same package, already get this right).
		return []types.Finding{finding}
	}

	var unsignedZones []string
	for _, zone := range data.DNSZones {
		if !zone.DNSSECEnabled {
			unsignedZones = append(unsignedZones, zone.Name)
		}
	}

	if len(unsignedZones) > 0 {
		finding.Count = len(unsignedZones)
		if data.IncludeDetails {
			entities := make([]types.AffectedEntity, len(unsignedZones))
			for i, name := range unsignedZones {
				entities[i] = types.AffectedEntity{Type: "dnsZone", Name: name}
			}
			finding.AffectedEntities = entities
		}
		finding.Details = map[string]interface{}{
			"unsignedZones":  unsignedZones,
			"totalZones":     len(data.DNSZones),
			"recommendation": "Enable DNSSEC signing on Active Directory-integrated DNS zones.",
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewDnssecDetector())
}
