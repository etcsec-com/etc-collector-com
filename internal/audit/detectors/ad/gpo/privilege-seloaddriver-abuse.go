package gpo

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// SeLoadDriverAbuseDetector checks if SeLoadDriverPrivilege is overly assigned
type SeLoadDriverAbuseDetector struct {
	audit.BaseDetector
}

func NewSeLoadDriverAbuseDetector() *SeLoadDriverAbuseDetector {
	return &SeLoadDriverAbuseDetector{
		BaseDetector: audit.NewBaseDetector("PRIVILEGE_SELOADDRIVER_ABUSE", audit.CategoryGPO),
	}
}

func (d *SeLoadDriverAbuseDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityCritical,
		Category:    string(d.Category()),
		Title:       "SeLoadDriverPrivilege Assigned to Non-Administrators",
		Description: "The SeLoadDriverPrivilege user right is assigned to accounts beyond Administrators. This privilege allows loading kernel-mode drivers, which can be abused to install rootkits, disable security software, and achieve full system compromise at the kernel level.",
		Count:       0,
	}

	sids := helpers.FindPrivilegeRight(data.GPOPolicies, func(pr *audit.PrivilegeRights) []string {
		return pr.SeLoadDriverPrivilege
	})

	unsafe := hasUnsafeSIDs(sids)
	finding.Count = len(unsafe)
	if len(unsafe) > 0 {
		finding.Details = map[string]interface{}{
			"unsafeSIDs":     unsafe,
			"recommendation": "Remove SeLoadDriverPrivilege from all non-administrator accounts.",
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
	audit.MustRegister(NewSeLoadDriverAbuseDetector())
}
