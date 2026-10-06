package serviceprincipals

import (
	"context"
	"time"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// Rotation ceilings sourced separately per credential type - Microsoft does
// not recommend the same lifetime for a client secret and a certificate:
//   - Secrets: "Microsoft recommends that you set an expiration value of less
//     than 12 months" for a client secret (Microsoft Learn, "Add and manage
//     app credentials in Microsoft Entra ID",
//     learn.microsoft.com/entra/identity-platform/how-to-add-credentials,
//     section "Add a client secret"). A secret still active past 12 months
//     has already outlived Microsoft's own recommended ceiling, independent
//     of whatever expiration date it was originally configured with.
//   - Certificates: "The recommended maximum lifetime for certificates is
//     180 days. This means that you should rotate your certificates at least
//     every 180 days." (Microsoft Learn, "Tutorial: Enforce secret and
//     certificate standards using application management policies",
//     learn.microsoft.com/entra/identity/enterprise-apps/tutorial-enforce-secret-standards,
//     section "Recommended practices for secrets and certificates" -
//     "Limit asymmetric key (certificate) lifetime to 180 days").
//
// Before this fix both credential types shared a single 1-year ceiling, so a
// certificate active for e.g. 200 days - already past Microsoft's 180-day
// recommendation - wrongly passed as fresh.
const (
	passwordStaleAfter = 365 * 24 * time.Hour
	certStaleAfter     = 180 * 24 * time.Hour
)

const (
	IDSPStaleCredential       = "SP_STALE_CREDENTIAL"
	CategorySPStaleCredential = audit.CategoryApplications
)

type SPStaleCredentialDetector struct {
	audit.BaseDetector
}

func NewSPStaleCredentialDetector() *SPStaleCredentialDetector {
	return &SPStaleCredentialDetector{
		BaseDetector: audit.NewBaseDetector(IDSPStaleCredential, CategorySPStaleCredential),
	}
}

func (d *SPStaleCredentialDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affectedSPs []types.ServicePrincipal
	now := data.Now

	isStale := func(cred types.AppCredential, staleAfter time.Duration) bool {
		return cred.StartDate.Before(now.Add(-staleAfter)) && cred.EndDate.After(now)
	}

	for _, sp := range data.AzureServicePrincipals {
		hasStale := false
		for _, cred := range sp.PasswordCredentials {
			if isStale(cred, passwordStaleAfter) {
				hasStale = true
				break
			}
		}
		if !hasStale {
			for _, cred := range sp.KeyCredentials {
				if isStale(cred, certStaleAfter) {
					hasStale = true
					break
				}
			}
		}

		if hasStale {
			affectedSPs = append(affectedSPs, sp)
		}
	}

	finding := types.Finding{
		Type:        IDSPStaleCredential,
		Severity:    types.SeverityHigh,
		Category:    string(CategorySPStaleCredential),
		Title:       "Service Principals with Stale Credentials",
		Description: "Service principal secrets active for more than 12 months, or certificates active for more than 180 days, still valid. These are Microsoft's own recommended rotation ceilings (client secrets: recommended expiration under 12 months; certificates: recommended maximum lifetime of 180 days) - rotate credentials at or before them.",
		Count:       len(affectedSPs),
	}

	if data.IncludeDetails && len(affectedSPs) > 0 {
		finding.AffectedEntities = helpers.ToAffectedServicePrincipalEntities(affectedSPs)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewSPStaleCredentialDetector())
}
