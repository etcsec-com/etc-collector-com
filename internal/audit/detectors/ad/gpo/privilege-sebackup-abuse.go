package gpo

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// SeBackupAbuseDetector checks if SeBackupPrivilege is overly assigned
type SeBackupAbuseDetector struct {
	audit.BaseDetector
}

func NewSeBackupAbuseDetector() *SeBackupAbuseDetector {
	return &SeBackupAbuseDetector{
		BaseDetector: audit.NewBaseDetector("PRIVILEGE_SEBACKUP_ABUSE", audit.CategoryGPO),
	}
}

func (d *SeBackupAbuseDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "SeBackupPrivilege Overly Assigned",
		Description: "The SeBackupPrivilege user right is assigned to accounts beyond Administrators and Backup Operators. This privilege allows reading any file on the system, bypassing all ACLs, enabling extraction of the NTDS.dit database, SAM hive, and other sensitive data.",
		Count:       0,
	}

	sids := helpers.FindPrivilegeRight(data.GPOPolicies, func(pr *audit.PrivilegeRights) []string {
		return pr.SeBackupPrivilege
	})

	// Also allow Backup Operators (S-1-5-32-551)
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
			"recommendation": "Limit SeBackupPrivilege to Administrators and Backup Operators only.",
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
	audit.MustRegister(NewSeBackupAbuseDetector())
}
