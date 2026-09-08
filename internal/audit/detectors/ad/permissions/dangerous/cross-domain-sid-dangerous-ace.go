package dangerous

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// CrossDomainSidDangerousACEDetector flags dangerous rights held by a trustee
// SID whose domain prefix does NOT match ours - a foreign-domain reference we
// cannot verify from this domain alone.
type CrossDomainSidDangerousACEDetector struct {
	audit.BaseDetector
}

// NewCrossDomainSidDangerousACEDetector creates the detector.
func NewCrossDomainSidDangerousACEDetector() *CrossDomainSidDangerousACEDetector {
	return &CrossDomainSidDangerousACEDetector{
		BaseDetector: audit.NewBaseDetector("CROSS_DOMAIN_SID_DANGEROUS_ACE", audit.CategoryPermissions),
	}
}

// Detect executes the detection.
func (d *CrossDomainSidDangerousACEDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	_, foreign := matchedOrphanACEs(data)

	uniqueObjects := helpers.GetUniqueObjects(foreign)
	totalInstances := len(foreign)

	finding := types.Finding{
		Type:     d.ID(),
		Severity: types.SeverityCritical,
		Category: string(d.Category()),
		Title:    "Dangerous ACE Granted to an Unverifiable Cross-Domain SID",
		Description: "A grant ACE (GenericAll/full control, WriteDACL, WriteOwner or GenericWrite) " +
			"names a trustee SID from a domain other than this one, with no matching well-known " +
			"or domain-local principal. A legitimate cross-domain grant of this kind normally " +
			"shows up here as a foreignSecurityPrincipal object - this collector currently only " +
			"counts those (see domain summary), it does not enumerate their individual SIDs, so " +
			"this exact SID cannot be confirmed against that count. It may be an intentional, " +
			"still-active trust grant, or a stale reference left behind by a trust that was later " +
			"removed or reconfigured - if the referenced domain is ever reachable again (trust " +
			"re-established, its DC compromised), this SID can be forged via sIDHistory to inherit " +
			"these rights immediately, with no dependency on RID recycling. Verify against the " +
			"domain's current trust relationships before deciding whether to remove it.",
		Count: len(uniqueObjects),
	}

	if totalInstances != len(uniqueObjects) {
		finding.TotalInstances = totalInstances
	}

	if data.IncludeDetails && len(uniqueObjects) > 0 {
		finding.AffectedEntities = audit.GetUniqueObjectEntities(foreign, data.ObjectByDN)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewCrossDomainSidDangerousACEDetector())
}
