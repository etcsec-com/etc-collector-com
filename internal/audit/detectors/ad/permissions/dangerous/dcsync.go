package dangerous

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// DCSyncDetector detects DS-Replication-Get-Changes rights (DCSync capability)
type DCSyncDetector struct {
	audit.BaseDetector
}

// NewDCSyncDetector creates a new detector
func NewDCSyncDetector() *DCSyncDetector {
	return &DCSyncDetector{
		BaseDetector: audit.NewBaseDetector("ACL_DS_REPLICATION_GET_CHANGES", audit.CategoryPermissions),
	}
}

// Detect executes the detection
func (d *DCSyncDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// DS-Replication-Get-Changes: 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2
	// DS-Replication-Get-Changes-All: 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2
	replicationGUIDs := map[string]bool{
		"1131f6aa-9c07-11d1-f79f-00c04fc2dcd2": true,
		"1131f6ad-9c07-11d1-f79f-00c04fc2dcd2": true,
	}

	var affected []types.ACLEntry

	for _, ace := range data.ACLEntries {
		if ace.ObjectType == "" || !replicationGUIDs[strings.ToLower(ace.ObjectType)] {
			continue
		}
		// A DENY ace grants nothing (DET_10 / T_065).
		if !audit.IsGrantACE(ace.AceType) {
			continue
		}
		// The replication GUID only means something as an extended right when
		// CONTROL_ACCESS is actually set on the ACE — otherwise ObjectType is
		// decorative (T_065/B_172: the detector never read AccessMask at all).
		if ace.AccessMask&types.MaskControlAccess == 0 {
			continue
		}
		// SYSTEM, Domain/Enterprise Admins, BUILTIN\Administrators, Domain
		// Controllers and Enterprise Domain Controllers hold replication
		// rights on every domain by construction — a DC cannot replicate
		// without them. Reporting them describes AD's design, not a
		// misconfiguration (T_065/B_172).
		if audit.IsBuiltinAdminTrustee(ace.Trustee) {
			continue
		}
		affected = append(affected, ace)
	}

	uniqueObjects := helpers.GetUniqueObjects(affected)
	totalInstances := len(affected)

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityCritical,
		Category:    string(d.Category()),
		Title:       "DS-Replication-Get-Changes Rights (DCSync)",
		Description: "Non-standard principals with directory replication rights. Enables DCSync attacks to extract all password hashes from the domain.",
		Count:       len(uniqueObjects),
		Details: map[string]interface{}{
			"risk":           "Complete domain compromise through password hash extraction.",
			"recommendation": "Remove replication rights from all non-DC accounts.",
		},
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
	audit.MustRegister(NewDCSyncDetector())
}
