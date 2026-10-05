package moderate

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// GenericWriteDetector detects GenericWrite permission on sensitive objects
type GenericWriteDetector struct {
	audit.BaseDetector
}

// NewGenericWriteDetector creates a new detector
func NewGenericWriteDetector() *GenericWriteDetector {
	return &GenericWriteDetector{
		BaseDetector: audit.NewBaseDetector("ACL_GENERICWRITE", audit.CategoryPermissions),
	}
}

// Detect executes the detection
func (d *GenericWriteDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// Raw GENERIC_WRITE bit.
	const genericWrite = 0x40000000
	// GenericWrite mapped to AD-specific rights when stored in ntSecurityDescriptor
	// (Windows maps generic bits to specific rights at ACE-write time - the raw
	// bit above is almost never what's actually on disk). Source:
	// Microsoft Learn, System.DirectoryServices.ActiveDirectoryRights,
	// member GenericWrite = 131112 = 0x00020028, the value .NET/dsacls actually
	// write; decomposed as READ_CONTROL (0x00020000) | ACTRL_DS_WRITE_PROP
	// (0x00000020) | ACTRL_DS_SELF (0x00000008) per MS-DTYP §2.4.3 (ACCESS_MASK)
	// and the MS-ADTS generic-rights mapping table for Directory Service
	// objects. Same table as ACL_GENERICALL's adFullControl (0x000F01FF).
	const adMappedGenericWrite = 0x00020028

	var affected []types.ACLEntry

	for _, ace := range data.ACLEntries {
		// A DENY ace grants nothing (DET_10).
		if !audit.IsGrantACE(ace.AceType) {
			continue
		}
		// SYSTEM / Domain Admins / Enterprise Admins / BUILTIN\Administrators
		// hold write access to every AD object by construction - see
		// genericall.go's note in this same package (1134/1167 objects on a
		// real domain without this filter).
		if audit.IsBuiltinAdminTrustee(ace.Trustee) {
			continue
		}
		if (ace.AccessMask & genericWrite) != 0 {
			affected = append(affected, ace)
			continue
		}
		if (ace.AccessMask & adMappedGenericWrite) == adMappedGenericWrite {
			affected = append(affected, ace)
		}
	}

	uniqueObjects := helpers.GetUniqueObjects(affected)
	totalInstances := len(affected)

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "ACL GenericWrite",
		Description: "GenericWrite permission on sensitive AD objects. Can modify many object attributes.",
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
	audit.MustRegister(NewGenericWriteDetector())
}
