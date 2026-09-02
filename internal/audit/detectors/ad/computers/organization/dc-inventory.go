package organization

// dc-inventory.go emits one INFO_DOMAIN_CONTROLLER finding per DC, each
// carrying a fully-typed dc AffectedEntity (v3.1.29 §5).
//
// Severity is info — these findings exist to expose DCs as first-class assets
// to the SaaS dispatcher, not to flag a vulnerability. A DC compromise is
// total domain compromise, so the SaaS lists them as the most critical
// asset class regardless of detected issues.

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// DomainControllerInventoryDetector emits the per-DC inventory.
type DomainControllerInventoryDetector struct {
	audit.BaseDetector
}

// NewDomainControllerInventoryDetector creates the detector.
func NewDomainControllerInventoryDetector() *DomainControllerInventoryDetector {
	return &DomainControllerInventoryDetector{
		BaseDetector: audit.NewBaseDetector("INFO_DOMAIN_CONTROLLER", audit.CategoryComputers),
	}
}

// Detect builds one finding per DC. Returns an empty slice when no DC is
// available (audit ran against a tenant with permission issues).
func (d *DomainControllerInventoryDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	if len(data.DomainControllers) == 0 {
		return nil
	}
	out := make([]types.Finding, 0, len(data.DomainControllers))
	for _, dc := range data.DomainControllers {
		ent := dcEntity(dc, data)
		f := types.Finding{
			Type:        d.ID(),
			Severity:    types.SeverityInfo,
			Category:    string(d.Category()),
			Title:       "Domain Controller",
			Description: "Inventory entry — exposes the DC as a first-class asset to the SaaS (FSMO roles, RODC flag, replication partners, site).",
			Count:       1,
		}
		if data.IncludeDetails {
			f.AffectedEntities = []types.AffectedEntity{ent}
		}
		out = append(out, f)
	}
	return out
}

// dcEntity assembles the typed dc AffectedEntity for a single DC. FSMO and
// replication partners come from data.DCInfo (populated during collectData);
// when absent, the entity still carries the basic computer fields with empty
// arrays — never nil — so the SaaS dispatcher gets a stable shape.
func dcEntity(c types.Computer, data *audit.DetectorData) types.AffectedEntity {
	name := c.SAMAccountName
	name = strings.TrimSuffix(name, "$")
	if name == "" {
		name = c.DNSHostName
	}
	ent := types.AffectedEntity{
		Type:                   types.EntityTypeDC,
		DN:                     c.DN,
		Name:                   name,
		DNSHostName:            c.DNSHostName,
		OperatingSystem:        c.OperatingSystem,
		OperatingSystemVersion: c.OperatingSystemVersion,
		FSMORoles:              []string{},
		ReplicationPartners:    []string{},
	}
	if data.DCInfo != nil {
		if meta := data.DCInfo[c.DN]; meta != nil {
			if len(meta.FSMORoles) > 0 {
				ent.FSMORoles = meta.FSMORoles
			}
			if len(meta.ReplicationPartners) > 0 {
				ent.ReplicationPartners = meta.ReplicationPartners
			}
			ent.Site = meta.Site
			ent.IsReadOnlyDC = meta.IsRODC
		}
	}
	return ent
}

func init() {
	audit.MustRegister(NewDomainControllerInventoryDetector())
}
