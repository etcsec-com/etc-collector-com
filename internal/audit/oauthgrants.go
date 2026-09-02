package audit

import (
	"strings"

	"github.com/etcsec-com/etc-collector/pkg/types"
)

// EnrichOAuth2Grants decorates each grant with resolved client/resource
// names (from the SP cache), splits the space-separated Scope string into
// a typed Scopes slice, and flags grants whose scopes intersect with the
// built-in dangerous-permissions list (Mail.*/Files.*/Directory.*/etc.).
//
// Mutates `grants` in place. Cheap — O(g + s) with two map-builds. Safe
// to call with sps == nil (the name resolutions are skipped, scope parsing
// + dangerous flagging still run).
//
// Backward compatibility: only ADDS to fields. The existing .Scope (string)
// and .ConsentType (string) are untouched, so the 3 detectors that read
// AzureOAuth2PermissionGrants today (excessive-delegated, consent-granted-
// tenant-wide, sp-disabled-with-permissions) keep working.
func EnrichOAuth2Grants(grants []types.OAuth2PermissionGrant, sps []types.ServicePrincipal) {
	var spByID map[string]*types.ServicePrincipal
	if len(sps) > 0 {
		spByID = make(map[string]*types.ServicePrincipal, len(sps))
		for i := range sps {
			spByID[sps[i].ID] = &sps[i]
		}
	}
	for i := range grants {
		g := &grants[i]
		if spByID != nil {
			if c, ok := spByID[g.ClientID]; ok {
				g.ClientName = c.DisplayName
				g.ClientAppID = c.AppID
			}
			if r, ok := spByID[g.ResourceID]; ok {
				g.ResourceName = r.DisplayName
			}
		}
		g.Scopes = strings.Fields(g.Scope)
		var dangerous []string
		for _, s := range g.Scopes {
			if _, isDang := types.DangerousGraphPermissions[s]; isDang {
				dangerous = append(dangerous, s)
			}
		}
		g.DangerousScopes = dangerous
		g.IsDangerous = len(dangerous) > 0
	}
}

// SummarizeOAuthGrants builds the OAuthGrantsSummary payload for the
// new top-level audit.oauthGrants JSON key. Pass already-enriched grants
// (call EnrichOAuth2Grants first) so DangerousCount is meaningful.
func SummarizeOAuthGrants(grants []types.OAuth2PermissionGrant) *types.OAuthGrantsSummary {
	out := &types.OAuthGrantsSummary{
		TotalGrants:   len(grants),
		ByConsentType: map[string]int{},
		Grants:        grants,
	}
	for _, g := range grants {
		if g.ConsentType != "" {
			out.ByConsentType[g.ConsentType]++
		}
		if g.IsDangerous {
			out.DangerousCount++
		}
	}
	return out
}
