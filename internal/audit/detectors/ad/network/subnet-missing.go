package network

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// SubnetMissingDetector checks for AD sites missing subnet definitions
type SubnetMissingDetector struct {
	audit.BaseDetector
}

// NewSubnetMissingDetector creates a new detector
func NewSubnetMissingDetector() *SubnetMissingDetector {
	return &SubnetMissingDetector{
		BaseDetector: audit.NewBaseDetector("SUBNET_MISSING", audit.CategoryNetwork),
	}
}

// Detect executes the detection
func (d *SubnetMissingDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// Check for sites without subnets
	var sitesWithoutSubnets []string

	for _, site := range data.Sites {
		hasSubnet := false
		for _, subnet := range data.Subnets {
			if strings.EqualFold(subnet.SiteDN, site.DistinguishedName) {
				hasSubnet = true
				break
			}
		}
		if !hasSubnet {
			sitesWithoutSubnets = append(sitesWithoutSubnets, site.Name)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityInfo,
		Category:    string(d.Category()),
		Title:       "AD Sites Missing Subnets",
		Description: "Sites without subnet definitions. Clients in undefined subnets will select DCs randomly, potentially crossing WAN links.",
		Count:       len(sitesWithoutSubnets),
		Details: map[string]interface{}{
			"totalSites":          len(data.Sites),
			"totalSubnets":        len(data.Subnets),
			"sitesWithoutSubnets": sitesWithoutSubnets,
		},
	}

	if data.IncludeDetails && len(sitesWithoutSubnets) > 0 {
		finding.AffectedEntities = toAffectedSiteEntities(sitesWithoutSubnets)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewSubnetMissingDetector())
}
