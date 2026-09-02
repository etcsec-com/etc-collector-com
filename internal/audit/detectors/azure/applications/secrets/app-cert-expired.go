package secrets

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

const (
	IDAppCertExpired       = "APP_CERT_EXPIRED"
	CategoryAppCertExpired = audit.CategoryApplications
)

type AppCertExpiredDetector struct {
	audit.BaseDetector
}

func NewAppCertExpiredDetector() *AppCertExpiredDetector {
	return &AppCertExpiredDetector{
		BaseDetector: audit.NewBaseDetector(IDAppCertExpired, CategoryAppCertExpired),
	}
}

func (d *AppCertExpiredDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affectedApps []types.AppRegistration
	now := data.Now

	for _, app := range data.AzureAppRegistrations {
		hasExpired := false
		for _, cert := range app.KeyCredentials {
			if cert.EndDate.Before(now) {
				hasExpired = true
				break
			}
		}

		if hasExpired {
			affectedApps = append(affectedApps, app)
		}
	}

	finding := types.Finding{
		Type:        IDAppCertExpired,
		Severity:    types.SeverityHigh,
		Category:    string(CategoryAppCertExpired),
		Title:       "Applications with Expired Certificates",
		Description: "Application certificates have expired. Remove expired certificates or rotate if still in use.",
		Count:       len(affectedApps),
	}

	if data.IncludeDetails && len(affectedApps) > 0 {
		finding.AffectedEntities = helpers.ToAffectedAppEntities(affectedApps)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewAppCertExpiredDetector())
}
