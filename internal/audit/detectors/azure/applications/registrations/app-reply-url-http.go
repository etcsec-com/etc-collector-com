package registrations

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

const (
	IDAppReplyURLHTTP       = "APP_REPLY_URL_HTTP"
	CategoryAppReplyURLHTTP = audit.CategoryApplications
)

type AppReplyURLHTTPDetector struct {
	audit.BaseDetector
}

func NewAppReplyURLHTTPDetector() *AppReplyURLHTTPDetector {
	return &AppReplyURLHTTPDetector{
		BaseDetector: audit.NewBaseDetector(IDAppReplyURLHTTP, CategoryAppReplyURLHTTP),
	}
}

func (d *AppReplyURLHTTPDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affectedApps []types.AppRegistration

	for _, app := range data.AzureAppRegistrations {
		hasHTTP := false
		for _, url := range app.ReplyURLs {
			if strings.HasPrefix(url, "http://") && !strings.Contains(url, "localhost") {
				hasHTTP = true
				break
			}
		}

		if hasHTTP {
			affectedApps = append(affectedApps, app)
		}
	}

	finding := types.Finding{
		Type:        IDAppReplyURLHTTP,
		Severity:    types.SeverityHigh,
		Category:    string(CategoryAppReplyURLHTTP),
		Title:       "Applications with HTTP Reply URLs",
		Description: "Applications using non-HTTPS reply URLs. Tokens transmitted over HTTP can be intercepted. Use HTTPS for all production reply URLs to prevent token interception.",
		Count:       len(affectedApps),
	}

	if data.IncludeDetails && len(affectedApps) > 0 {
		finding.AffectedEntities = helpers.ToAffectedAppEntities(affectedApps)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewAppReplyURLHTTPDetector())
}
