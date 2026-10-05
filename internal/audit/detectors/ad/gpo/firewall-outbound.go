package gpo

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// FirewallOutboundDetector checks if Windows Firewall outbound connections are blocked by default
type FirewallOutboundDetector struct {
	audit.BaseDetector
}

func NewFirewallOutboundDetector() *FirewallOutboundDetector {
	return &FirewallOutboundDetector{
		BaseDetector: audit.NewBaseDetector("FIREWALL_OUTBOUND_NOT_BLOCKED", audit.CategoryGPO),
	}
}

func (d *FirewallOutboundDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityLow,
		Category:    string(d.Category()),
		Title:       "Windows Firewall Outbound Not Blocked",
		Description: "Windows Firewall does not block outbound connections by default for the domain profile. Allowing unrestricted outbound connections enables malware to communicate with C2 servers, exfiltrate data, and establish reverse shells.",
		Count:       0,
	}

	v := helpers.FindRegistrySettingInt(data.GPOPolicies, func(rs *audit.RegistrySettings) *int {
		return rs.FirewallOutboundAction
	})

	// DefaultOutboundAction: 0 = allow (default), 1 = block
	if v == nil || *v != 1 {
		finding.Count = 1
		finding.Details = map[string]interface{}{
			"recommendation": "Configure Windows Firewall to block outbound connections by default and create explicit allow rules for required traffic.",
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewFirewallOutboundDetector())
}
