package moderate

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// GPOLinkPoisoningDetector detects weak ACLs on the Group Policy container.
//
// Two defects fixed here:
//  1. This detector never checked ace.AceType, so a DENY ACE carrying the
//     GenericAll/GenericWrite/WriteDACL bits was counted the same as an
//     ALLOW grant - the same bug shape fixed elsewhere in this repo (see
//     everyone-in-acl.go, writedacl.go, genericall.go, self-membership.go,
//     writeowner.go). A DENY ACE grants nothing. Fixed with audit.IsGrantACE,
//     the same helper those fixes use.
//  2. The collector only gathers the ACL of the single Policies container
//     (CN=Policies,CN=System) - not the ACL of each individual GPO object -
//     so this detector can never name a specific vulnerable GPO the way its
//     old title/description implied. Retitled to describe what is actually
//     measured: the container whose ACL controls who can create/link new
//     GPOs and, once granted here, poison links domain-wide.
type GPOLinkPoisoningDetector struct {
	audit.BaseDetector
}

// NewGPOLinkPoisoningDetector creates a new detector
func NewGPOLinkPoisoningDetector() *GPOLinkPoisoningDetector {
	return &GPOLinkPoisoningDetector{
		BaseDetector: audit.NewBaseDetector("GPO_LINK_POISONING", audit.CategoryPermissions),
	}
}

// Detect executes the detection
func (d *GPOLinkPoisoningDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	const genericWrite = 0x40000000
	const genericAll = 0x10000000
	const writeDACL = 0x00040000

	var affected []types.ACLEntry

	for _, ace := range data.ACLEntries {
		if !audit.IsGrantACE(ace.AceType) {
			continue
		}
		isGPOContainer := strings.Contains(ace.ObjectDN, "CN=Policies,CN=System")
		hasDangerousPermission := (ace.AccessMask&genericAll) != 0 ||
			(ace.AccessMask&genericWrite) != 0 ||
			(ace.AccessMask&writeDACL) != 0

		if isGPOContainer && hasDangerousPermission {
			affected = append(affected, ace)
		}
	}

	uniqueObjects := helpers.GetUniqueObjects(affected)
	totalInstances := len(affected)

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "Weak ACL on the Group Policy Container",
		Description: "Weak ACL on the GPO container (CN=Policies,CN=System) - the collector reads this container's ACL, not each individual GPO's own ACL, so a specific vulnerable GPO cannot be named. A non-admin grant here allows creating or relinking GPOs domain-wide, which can be used to execute code on targeted systems.",
		Count:       len(uniqueObjects),
	}

	if totalInstances != len(uniqueObjects) {
		finding.TotalInstances = totalInstances
	}

	if data.IncludeDetails && len(uniqueObjects) > 0 {
		entities := make([]types.AffectedEntity, len(uniqueObjects))
		for i, dn := range uniqueObjects {
			entities[i] = types.AffectedEntity{
				Type: "gpo",
				DN:   dn,
			}
		}
		finding.AffectedEntities = entities
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewGPOLinkPoisoningDetector())
}
