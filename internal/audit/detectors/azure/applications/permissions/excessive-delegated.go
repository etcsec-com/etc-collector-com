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
			// 10 scopes is an etc-collector product threshold, not a
			// Microsoft- or CIS-sourced limit. Checked against Microsoft's
			// own permissions/consent documentation (learn.microsoft.com/
			// en-us/entra/identity-platform/permissions-consent-overview,
			// learn.microsoft.com/en-us/graph/permissions-overview) and the
			// CIS Microsoft 365 Foundations Benchmark: neither defines a
			// numeric cap on delegated-permission scope count. This is a
			// volume-based repere flagging grants worth reviewing, not a
			// documented compliance requirement.
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
