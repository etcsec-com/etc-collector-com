package network

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// DnsWildcardDetector checks for DNS wildcard records
type DnsWildcardDetector struct {
	audit.BaseDetector
}

// NewDnsWildcardDetector creates a new detector
func NewDnsWildcardDetector() *DnsWildcardDetector {
	return &DnsWildcardDetector{
		BaseDetector: audit.NewBaseDetector("DNS_WILDCARD_RECORDS", audit.CategoryNetwork),
	}
}

// Detect executes the detection
func (d *DnsWildcardDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "DNS Wildcard Records Detected",
		Description: "Wildcard DNS records (*.domain) can be exploited for MITM attacks. Review and remove unnecessary wildcards.",
		Count:       0,
	}

	if len(data.DNSZones) == 0 {
		return []types.Finding{finding}
	}

	var affectedZones []string
	for _, zone := range data.DNSZones {
		if len(zone.WildcardRecords) > 0 {
			affectedZones = append(affectedZones, zone.Name)
		}
	}

	if len(affectedZones) > 0 {
		finding.Count = len(affectedZones)
		finding.Details = map[string]interface{}{
			"affectedZones":  affectedZones,
			"recommendation": "Remove wildcard DNS records unless specifically required.",
		}
		if data.IncludeDetails {
			finding.AffectedEntities = toAffectedZoneEntities(affectedZones)
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewDnsWildcardDetector())
}
