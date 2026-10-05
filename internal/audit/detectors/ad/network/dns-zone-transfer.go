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
	var notDetermined []string
	for _, zt := range data.NetworkProbes.ZoneTransfers {
		switch {
		case zt.Allowed:
			vulnerableZones = append(vulnerableZones, zt.Zone)
		case !zt.Determined:
			notDetermined = append(notDetermined, zt.Zone)
		}
	}

	if len(vulnerableZones) > 0 || len(notDetermined) > 0 {
		finding.Count = len(vulnerableZones)
		details := map[string]interface{}{}
		if len(vulnerableZones) > 0 {
			details["vulnerableZones"] = vulnerableZones
			details["recommendation"] = "Restrict DNS zone transfers to authorized secondary DNS servers only."
		}
		if len(notDetermined) > 0 {
			details["notDetermined"] = notDetermined
			details["notDeterminedReason"] = "DNS zone transfer probe could not reach the domain controller (e.g. hostname did not resolve) - these zones could not be tested"
		}
		finding.Details = details
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewDnsZoneTransferDetector())
}
