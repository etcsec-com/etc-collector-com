package settings

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

const (
	AZ_SELF_SERVICE_GROUPS_OPEN = "AZ_SELF_SERVICE_GROUPS_OPEN"
)

type SelfServiceGroupsOpenDetector struct {
	audit.BaseDetector
}

func NewSelfServiceGroupsOpenDetector() *SelfServiceGroupsOpenDetector {
	return &SelfServiceGroupsOpenDetector{
		BaseDetector: audit.NewBaseDetector(
			AZ_SELF_SERVICE_GROUPS_OPEN,
			audit.CategoryConfig,
		),
	}
}

func (d *SelfServiceGroupsOpenDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "Self-Service Group Creation Open",
		Description: "Users can create M365 groups/teams without restrictions, leading to group sprawl.",
		Count:       0,
	}

	if data.AzureTenantConfig == nil {
		return []types.Finding{finding}
	}

	if data.AzureTenantConfig.GroupCreationPolicy == "" {
		finding.Count = 1
		if data.IncludeDetails {
			finding.AffectedEntities = []types.AffectedEntity{
				{
					Type:        "tenant",
					DN:          "tenant",
					Name:        "Azure AD Tenant",
					Description: "Self-service group creation is unrestricted",
				},
			}
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewSelfServiceGroupsOpenDetector())
}
