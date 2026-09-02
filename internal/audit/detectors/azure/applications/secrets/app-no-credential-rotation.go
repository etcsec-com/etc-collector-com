package secrets

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

const (
	IDAppNoCredentialRotation       = "APP_NO_CREDENTIAL_ROTATION"
	CategoryAppNoCredentialRotation = audit.CategoryApplications
)

type AppNoCredentialRotationDetector struct {
	audit.BaseDetector
}

func NewAppNoCredentialRotationDetector() *AppNoCredentialRotationDetector {
	return &AppNoCredentialRotationDetector{
		BaseDetector: audit.NewBaseDetector(IDAppNoCredentialRotation, CategoryAppNoCredentialRotation),
	}
}

func (d *AppNoCredentialRotationDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affectedApps []types.AppRegistration
	oneYearAgo := data.Now.AddDate(-1, 0, 0)

	for _, app := range data.AzureAppRegistrations {
		if len(app.PasswordCredentials) == 0 {
			continue
		}

		allOld := true
		for _, cred := range app.PasswordCredentials {
			if cred.StartDate.After(oneYearAgo) {
				allOld = false
				break
			}
		}

		if allOld {
			affectedApps = append(affectedApps, app)
		}
	}

	finding := types.Finding{
		Type:        IDAppNoCredentialRotation,
		Severity:    types.SeverityHigh,
		Category:    string(CategoryAppNoCredentialRotation),
		Title:       "No Credential Rotation",
		Description: "Application credentials created more than 1 year ago without newer replacements. Implement regular credential rotation (every 90-180 days).",
		Count:       len(affectedApps),
	}

	if data.IncludeDetails && len(affectedApps) > 0 {
		finding.AffectedEntities = helpers.ToAffectedAppEntities(affectedApps)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewAppNoCredentialRotationDetector())
}
