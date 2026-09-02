package moderate

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// EveryoneInACLDetector detects Everyone/Authenticated Users with write permissions
type EveryoneInACLDetector struct {
	audit.BaseDetector
}

// NewEveryoneInACLDetector creates a new detector
func NewEveryoneInACLDetector() *EveryoneInACLDetector {
	return &EveryoneInACLDetector{
		BaseDetector: audit.NewBaseDetector("EVERYONE_IN_ACL", audit.CategoryPermissions),
	}
}

// Detect executes the detection
func (d *EveryoneInACLDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	const everyoneSID = "S-1-1-0"
	const authenticatedUsersSID = "S-1-5-11"

	// The mask used to be 0x00020000, commented "ADS_RIGHT_DS_WRITE_PROP".
	// 0x00020000 is READ_CONTROL — the right to READ the security descriptor,
	// which Authenticated Users holds on virtually every object in a domain, so
	// the detector fired on 1167 of 1167 objects (T_024). WRITE_PROP is 0x20,
	// as the repo declares in four other places (types.MaskWriteProperty,
	// aclentry.go:19, gpo/dangerous-permissions.go:29, adcs/esc4.go:30).
	//
	// The check is "Everyone/Authenticated Users can WRITE", so every write-class
	// right counts, not just WRITE_PROP: a group-writable DACL or owner is at
	// least as dangerous as a writable property.
	const writeMask = types.MaskWriteProperty | // 0x00000020
		types.MaskWriteDACL | // 0x00040000
		types.MaskWriteOwner | // 0x00080000
		types.MaskGenericWrite | // 0x40000000
		types.MaskGenericAll // 0x10000000

	var affected []types.ACLEntry

	for _, ace := range data.ACLEntries {
		// A DENY ace granting nothing is not an over-permission (DET_10).
		if !audit.IsGrantACE(ace.AceType) {
			continue
		}
		isEveryone := ace.Trustee == everyoneSID || ace.Trustee == authenticatedUsersSID
		hasWrite := (ace.AccessMask & writeMask) != 0

		if isEveryone && hasWrite {
			affected = append(affected, ace)
		}
	}

	uniqueObjects := helpers.GetUniqueObjects(affected)
	totalInstances := len(affected)

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "Everyone in ACL",
		Description: "Everyone or Authenticated Users with write permissions in ACL. Overly permissive access.",
		Count:       len(uniqueObjects),
	}

	if totalInstances != len(uniqueObjects) {
		finding.TotalInstances = totalInstances
	}

	if data.IncludeDetails && len(uniqueObjects) > 0 {
		finding.AffectedEntities = audit.GetUniqueObjectEntities(affected, data.ObjectByDN)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewEveryoneInACLDetector())
}
