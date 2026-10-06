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
	// This only measures "no new credential in 12 months" - it does not
	// verify a 90-180 day rotation cadence. Microsoft's own stated
	// recommendation (learn.microsoft.com/en-us/entra/identity-platform/
	// how-to-add-credentials) is "set an expiration value of less than 12
	// months" - no specific 90-180-day rotation-cadence requirement, and no
	// "6 months preferred" figure, is published. Title and description
	// below are scoped to exactly what this measures and do not overclaim
	// the source.
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
		Title:       "No Credential Rotation in Over a Year",
		Description: "No password credential has been created for this application in the past 12 months, meaning secrets have not been rotated in over a year. Microsoft recommends rotating secrets more frequently than that (\"less than 12 months\"); it does not publish a specific preferred cadence.",
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
