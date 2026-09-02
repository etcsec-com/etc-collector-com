package network

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// DNSZoneAUCreateChildDetector detects DNS zones where Authenticated Users can create records
type DNSZoneAUCreateChildDetector struct {
	audit.BaseDetector
}

// NewDNSZoneAUCreateChildDetector creates a new detector
func NewDNSZoneAUCreateChildDetector() *DNSZoneAUCreateChildDetector {
	return &DNSZoneAUCreateChildDetector{
		BaseDetector: audit.NewBaseDetector("DNS_ZONE_AU_CREATE_CHILD", audit.CategoryNetwork),
	}
}

// Detect executes the detection
func (d *DNSZoneAUCreateChildDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// Check ACLs on DNS zone objects for Authenticated Users (S-1-5-11) or Everyone (S-1-1-0)
	// having CreateChild permission (ADS_RIGHT_DS_CREATE_CHILD = 0x1)
	const createChild = 0x1

	// Check ACLs on DNS zone objects using the zone's actual DN
	var vulnerableZones []string
	for _, zone := range data.DNSZones {
		if zone.DN == "" {
			continue
		}
		for _, acl := range data.ACLEntries {
			if !strings.EqualFold(acl.ObjectDN, zone.DN) {
				continue
			}
			// Check if Authenticated Users or Everyone has CreateChild
			// ACE type may be ACCESS_ALLOWED or ACCESS_ALLOWED_OBJECT
			if (acl.Trustee == "S-1-5-11" || acl.Trustee == "S-1-1-0") &&
				(strings.EqualFold(acl.AceType, "ACCESS_ALLOWED") || strings.EqualFold(acl.AceType, "ACCESS_ALLOWED_OBJECT")) &&
				(acl.AccessMask&createChild) != 0 {
				vulnerableZones = append(vulnerableZones, zone.Name)
				break
			}
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "DNS Zone Allows Authenticated Users to Create Records",
		Description: "DNS zones where Authenticated Users can create child objects allow any domain user to add arbitrary DNS records, enabling man-in-the-middle and credential theft attacks.",
		Count:       len(vulnerableZones),
	}

	if data.IncludeDetails && len(vulnerableZones) > 0 {
		entities := make([]types.AffectedEntity, len(vulnerableZones))
		for i, name := range vulnerableZones {
			entities[i] = types.AffectedEntity{Type: "dnsZone", Name: name}
		}
		finding.AffectedEntities = entities
		finding.Details = map[string]interface{}{
			"vulnerableZones": vulnerableZones,
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewDNSZoneAUCreateChildDetector())
}
