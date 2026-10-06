package gpo

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// SeRestoreAbuseDetector checks if SeRestorePrivilege is overly assigned
type SeRestoreAbuseDetector struct {
	audit.BaseDetector
}

func NewSeRestoreAbuseDetector() *SeRestoreAbuseDetector {
	return &SeRestoreAbuseDetector{
		BaseDetector: audit.NewBaseDetector("PRIVILEGE_SERESTORE_ABUSE", audit.CategoryGPO),
	}
}

func (d *SeRestoreAbuseDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "SeRestorePrivilege Overly Assigned",
		Description: "The SeRestorePrivilege user right is assigned beyond Administrators and Backup Operators. This privilege allows writing to any file and registry key, bypassing ACLs, enabling DLL hijacking, service binary replacement, and other privilege escalation techniques.",
		Count:       0,
	}

	sids := helpers.FindPrivilegeRight(data.GPOPolicies, func(pr *audit.PrivilegeRights) []string {
		return pr.SeRestorePrivilege
	})

	safe := map[string]bool{
		"S-1-5-32-544": true, // Administrators
		"S-1-5-32-551": true, // Backup Operators
		"S-1-5-18":     true, // SYSTEM
	}
	var unsafe []string
	for _, sid := range sids {
		if !safe[sid] {
			unsafe = append(unsafe, sid)
		}
	}

	finding.Count = len(unsafe)
	if len(unsafe) > 0 {
		finding.Details = map[string]interface{}{
			"unsafeSIDs":     unsafe,
			"recommendation": "Limit SeRestorePrivilege to Administrators and Backup Operators only.",
		}
		if data.IncludeDetails {
			entities := make([]types.AffectedEntity, len(unsafe))
			for i, sid := range unsafe {
				entities[i] = audit.SIDToEntityWithCache(sid, data)
			}
			finding.AffectedEntities = entities
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewSeRestoreAbuseDetector())
}
