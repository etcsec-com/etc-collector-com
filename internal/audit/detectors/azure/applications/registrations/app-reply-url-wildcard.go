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
		Title:       "Applications with Wildcard Reply URLs",
		Description: "Applications using wildcard reply URLs. Attackers can redirect tokens to malicious endpoints. Use explicit URLs for production applications.",
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
