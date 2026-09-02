package network

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// DnsZoneTransferDetector checks for unrestricted DNS zone transfers
type DnsZoneTransferDetector struct {
	audit.BaseDetector
}

// NewDnsZoneTransferDetector creates a new detector
func NewDnsZoneTransferDetector() *DnsZoneTransferDetector {
	return &DnsZoneTransferDetector{
		BaseDetector: audit.NewBaseDetector("DNS_ZONE_TRANSFER_UNRESTRICTED", audit.CategoryNetwork),
	}
}

// Detect executes the detection
func (d *DnsZoneTransferDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "DNS Zone Transfer Unrestricted",
		Description: "DNS zones allowing zone transfers to any server. Attackers can enumerate DNS records to map internal network topology.",
		Count:       0,
	}

	// This detector requires network probes (opt-in)
	if data.NetworkProbes == nil {
		return []types.Finding{finding}
	}

	var vulnerableZones []string
	for _, zt := range data.NetworkProbes.ZoneTransfers {
		if zt.Allowed {
			vulnerableZones = append(vulnerableZones, zt.Zone)
		}
	}

	if len(vulnerableZones) > 0 {
		finding.Count = len(vulnerableZones)
		finding.Details = map[string]interface{}{
			"vulnerableZones": vulnerableZones,
			"recommendation":  "Restrict DNS zone transfers to authorized secondary DNS servers only.",
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewDnsZoneTransferDetector())
}
