package settings

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

const (
	AZ_LINKEDIN_SYNC_ENABLED = "AZ_LINKEDIN_SYNC_ENABLED"
)

type LinkedInSyncEnabledDetector struct {
	audit.BaseDetector
}

func NewLinkedInSyncEnabledDetector() *LinkedInSyncEnabledDetector {
	return &LinkedInSyncEnabledDetector{
		BaseDetector: audit.NewBaseDetector(
			AZ_LINKEDIN_SYNC_ENABLED,
			audit.CategoryConfig,
		),
	}
}

func (d *LinkedInSyncEnabledDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityLow,
		Category:    string(d.Category()),
		Title:       "LinkedIn Account Synchronization Enabled",
		Description: "LinkedIn data synchronization is enabled. This shares organizational data with LinkedIn.",
		Count:       0,
	}

	if data.AzureTenantConfig == nil {
		return []types.Finding{finding}
	}

	if data.AzureTenantConfig.LinkedInSyncEnabled {
		finding.Count = 1
		if data.IncludeDetails {
			finding.AffectedEntities = []types.AffectedEntity{
				{
					Type:        "tenant",
					DN:          "tenant",
					Name:        "Azure AD Tenant",
					Description: "LinkedIn account synchronization is enabled",
				},
			}
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewLinkedInSyncEnabledDetector())
}
