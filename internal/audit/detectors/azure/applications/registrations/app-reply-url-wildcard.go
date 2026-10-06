package registrations

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

const (
	IDAppReplyURLWildcard       = "APP_REPLY_URL_WILDCARD"
	CategoryAppReplyURLWildcard = audit.CategoryApplications
)

type AppReplyURLWildcardDetector struct {
	audit.BaseDetector
}

func NewAppReplyURLWildcardDetector() *AppReplyURLWildcardDetector {
	return &AppReplyURLWildcardDetector{
		BaseDetector: audit.NewBaseDetector(IDAppReplyURLWildcard, CategoryAppReplyURLWildcard),
	}
}

func (d *AppReplyURLWildcardDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affectedApps []types.AppRegistration

	// Same collection scope as APP_REPLY_URL_HTTP: AppRegistration.ReplyURLs
	// only carries the "web" platform's redirectUris (internal/providers/
	// azure/client.go: app.ReplyURLs = web.GetRedirectUris()). The "spa" and
	// "publicClient" platform redirect URI lists (learn.microsoft.com/
	// en-us/entra/identity-platform/reference-app-manifest) are not
	// collected, so a wildcard confined to those platforms is not seen here
	// (non vu). Same out-of-scope collection gap as the HTTP check.
	for _, app := range data.AzureAppRegistrations {
		hasWildcard := false
		for _, url := range app.ReplyURLs {
			if strings.Contains(url, "*") {
				hasWildcard = true
				break
			}
		}

		if hasWildcard {
			affectedApps = append(affectedApps, app)
		}
	}

	finding := types.Finding{
		Type:        IDAppReplyURLWildcard,
		Severity:    types.SeverityHigh,
		Category:    string(CategoryAppReplyURLWildcard),
		Title:       "Web Applications with Wildcard Reply URLs",
		Description: "Applications using wildcard reply URLs on their web platform registration. Attackers can redirect tokens to malicious endpoints. Use explicit URLs for production applications. Covers the web platform's redirect URIs only; SPA and public-client (mobile/desktop) redirect URIs are not currently collected and are not evaluated by this check.",
		Count:       len(affectedApps),
	}

	if data.IncludeDetails && len(affectedApps) > 0 {
		finding.AffectedEntities = helpers.ToAffectedAppEntities(affectedApps)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewAppReplyURLWildcardDetector())
}
