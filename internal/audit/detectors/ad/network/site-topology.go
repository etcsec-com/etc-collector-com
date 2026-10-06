package network

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// SiteTopologyDetector checks for AD site topology issues
type SiteTopologyDetector struct {
	audit.BaseDetector
}

// NewSiteTopologyDetector creates a new detector
func NewSiteTopologyDetector() *SiteTopologyDetector {
	return &SiteTopologyDetector{
		BaseDetector: audit.NewBaseDetector("SITE_TOPOLOGY_ISSUES", audit.CategoryNetwork),
	}
}

// Detect executes the detection
func (d *SiteTopologyDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// Sites without servers (DCs) are problematic
	var sitesWithoutDc []string

	for _, site := range data.Sites {
		if len(site.Servers) == 0 {
			sitesWithoutDc = append(sitesWithoutDc, site.Name)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityLow,
		Category:    string(d.Category()),
		Title:       "AD Sites Without a Domain Controller",
		Description: "Sites with zero domain controllers force clients in that site to authenticate against a DC in another site, increasing latency and WAN traffic. This check only counts sites with no DC assigned - it does not evaluate site links, replication costs, or subnet-to-site mappings, none of which are collected today.",
		Count:       len(sitesWithoutDc),
		Details: map[string]interface{}{
			"sitesWithoutDc": sitesWithoutDc,
		},
	}

	if len(sitesWithoutDc) > 0 {
		finding.AffectedEntities = toAffectedSiteEntities(sitesWithoutDc)
	}

	return []types.Finding{finding}
}

func toAffectedSiteEntities(names []string) []types.AffectedEntity {
	entities := make([]types.AffectedEntity, len(names))
	for i, name := range names {
		entities[i] = types.AffectedEntity{
			Type: "site",
			Name: name,
		}
	}
	return entities
}

func init() {
	audit.MustRegister(NewSiteTopologyDetector())
}
