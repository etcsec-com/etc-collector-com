package network

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// DnsWildcardDetector checks for DNS wildcard records.
//
// Source check: no ANSSI/CIS/NIST/Microsoft compliance control sets a
// numeric or normative requirement against wildcard DNS records in AD-
// integrated DNS zones - this is not a cited compliance requirement, it is
// an etc-collector product heuristic. The underlying threat is real and
// documented outside any compliance framework: ADIDNS poisoning via
// wildcard record creation lets any authenticated user (default ADIDNS
// permissions grant record creation domain-wide) respond to unmatched name
// queries and coerce/relay authentication - see NetSPI, "Beyond LLMNR/NBNS
// Spoofing - Exploiting Active Directory-Integrated DNS" and Elastic's
// "Potential ADIDNS Poisoning via Wildcard Record Creation" detection rule.
// Kept as a Medium product-benchmark finding, not upgraded to a compliance
// citation that does not exist.
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
