package network

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// DnsDynamicUpdateDetector checks for insecure DNS dynamic updates
type DnsDynamicUpdateDetector struct {
	audit.BaseDetector
}

// NewDnsDynamicUpdateDetector creates a new detector
func NewDnsDynamicUpdateDetector() *DnsDynamicUpdateDetector {
	return &DnsDynamicUpdateDetector{
		BaseDetector: audit.NewBaseDetector("DNS_DYNAMIC_UPDATE_INSECURE", audit.CategoryNetwork),
	}
}

// Detect executes the detection
func (d *DnsDynamicUpdateDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "DNS Dynamic Update Insecure",
		Description: "DNS zones allowing non-secure dynamic updates. Attackers can inject malicious DNS records without authentication.",
		Count:       0,
	}

	if len(data.DNSZones) == 0 {
		return []types.Finding{finding}
	}

	var insecureZones []string
	for _, zone := range data.DNSZones {
		if zone.DynamicUpdate == "nonsecure" {
			insecureZones = append(insecureZones, zone.Name)
		}
	}

	if len(insecureZones) > 0 {
		finding.Count = len(insecureZones)
		finding.Details = map[string]interface{}{
			"insecureZones":  insecureZones,
			"recommendation": "Configure DNS zones to use 'Secure only' dynamic updates.",
		}
		if data.IncludeDetails {
			finding.AffectedEntities = toAffectedZoneEntities(insecureZones)
		}
	}

	return []types.Finding{finding}
}

func toAffectedZoneEntities(names []string) []types.AffectedEntity {
	entities := make([]types.AffectedEntity, len(names))
	for i, name := range names {
		entities[i] = types.AffectedEntity{
			Type: types.EntityTypeDNSZone,
			Name: name,
		}
	}
	return entities
}

func init() {
	audit.MustRegister(NewDnsDynamicUpdateDetector())
}
