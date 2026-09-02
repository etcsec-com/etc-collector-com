package permissions

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

const (
	IDExcessiveDelegated       = "APP_EXCESSIVE_DELEGATED"
	CategoryExcessiveDelegated = audit.CategoryApplications
)

type ExcessiveDelegatedDetector struct {
	audit.BaseDetector
}

func NewExcessiveDelegatedDetector() *ExcessiveDelegatedDetector {
	return &ExcessiveDelegatedDetector{
		BaseDetector: audit.NewBaseDetector(IDExcessiveDelegated, CategoryExcessiveDelegated),
	}
}

func (d *ExcessiveDelegatedDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affectedGrants []types.OAuth2PermissionGrant

	for _, grant := range data.AzureOAuth2PermissionGrants {
		if grant.ConsentType == "AllPrincipals" {
			scopes := strings.Fields(grant.Scope)
			if len(scopes) > 10 {
				affectedGrants = append(affectedGrants, grant)
			}
		}
	}

	finding := types.Finding{
		Type:        IDExcessiveDelegated,
		Severity:    types.SeverityHigh,
		Category:    string(CategoryExcessiveDelegated),
		Title:       "App with Excessive Delegated Permissions",
		Description: "Applications with many delegated permission scopes granted tenant-wide. Apply principle of least privilege.",
		Count:       len(affectedGrants),
	}

	if data.IncludeDetails && len(affectedGrants) > 0 {
		finding.AffectedEntities = helpers.ToAffectedOAuth2GrantEntities(affectedGrants)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewExcessiveDelegatedDetector())
}
