package other

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// PrivilegedGroupChangesDetector detects recent membership changes in privileged groups
type PrivilegedGroupChangesDetector struct {
	audit.BaseDetector
}

// NewPrivilegedGroupChangesDetector creates a new detector
func NewPrivilegedGroupChangesDetector() *PrivilegedGroupChangesDetector {
	return &PrivilegedGroupChangesDetector{
		BaseDetector: audit.NewBaseDetector("PRIVILEGED_GROUP_MEMBER_CHANGES", audit.CategoryAdvanced),
	}
}

// Detect executes the detection
func (d *PrivilegedGroupChangesDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	count := 0
	cutoff := data.Now.AddDate(0, 0, -7)

	for _, members := range data.PrivilegedGroupMemberChanges {
		for _, changeTime := range members {
			if changeTime.After(cutoff) {
				count++
			}
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityInfo,
		Category:    string(d.Category()),
		Title:       "Privileged Group Membership Recently Changed",
		Description: "Members have been added to or removed from privileged groups (Domain Admins, Enterprise Admins, Schema Admins, etc.) within the last 7 days. Frequent changes may indicate compromise or unauthorized privilege escalation.",
		Count:       count,
	}

	if data.IncludeDetails && count > 0 {
		var entities []types.AffectedEntity
		for groupDN, members := range data.PrivilegedGroupMemberChanges {
			for memberDN, changeTime := range members {
				if changeTime.After(cutoff) {
					entities = append(entities, types.AffectedEntity{
						Type: "groupMemberChange",
						Name: groupDN + " → " + memberDN,
					})
				}
			}
		}
		finding.AffectedEntities = entities
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewPrivilegedGroupChangesDetector())
}
