package moderate

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// T_036 — ACL_FORCECHANGEPASSWORD lived here too, with a byte-identical
// predicate (same extended-right GUID, same loop, same severity, same
// category): a copy-paste twin that made every force-password-reset delegation
// appear twice in the report. It carried no compliance mapping, so removing it
// costs nothing; ACL_USER_FORCE_CHANGE_PASSWORD survives because its name
// matches the AD right, as rendered by aclentry.go's AccessMaskToRight.
// See detectors/ad/dedup.go, rule R1.

// UserForceChangePasswordDetector detects User-Force-Change-Password rights
type UserForceChangePasswordDetector struct {
	audit.BaseDetector
}

// NewUserForceChangePasswordDetector creates a new detector
func NewUserForceChangePasswordDetector() *UserForceChangePasswordDetector {
	return &UserForceChangePasswordDetector{
		BaseDetector: audit.NewBaseDetector("ACL_USER_FORCE_CHANGE_PASSWORD", audit.CategoryPermissions),
	}
}

// Detect executes the detection
func (d *UserForceChangePasswordDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// User-Force-Change-Password: 00299570-246d-11d0-a768-00aa006e0529
	const forceChangePasswordGUID = "00299570-246d-11d0-a768-00aa006e0529"

	var affected []types.ACLEntry

	for _, ace := range data.ACLEntries {
		if strings.ToLower(ace.ObjectType) == forceChangePasswordGUID {
			affected = append(affected, ace)
		}
	}

	uniqueObjects := helpers.GetUniqueObjects(affected)
	totalInstances := len(affected)

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "User-Force-Change-Password Rights",
		Description: "Principals with rights to force password change on user accounts. Can reset passwords to take over accounts.",
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
	audit.MustRegister(NewUserForceChangePasswordDetector())
}
