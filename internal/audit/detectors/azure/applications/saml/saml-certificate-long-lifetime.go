package saml

import (
	"context"
	"fmt"
	"time"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// samlLongExpiryLimit tracks Microsoft Entra ID's own ceiling for an
// auto-created SAML signing certificate, not an independently-sourced
// security recommendation: "By default, Microsoft Entra ID configures a
// certificate to expire after three years when it is created
// automatically during SAML single sign-on configuration... you can set
// any date between the current date and three years after the current
// date" (Microsoft Learn, "Certificate signing options in a SAML token",
// learn.microsoft.com/entra/identity/enterprise-apps/certificate-signing-options,
// section "Change certificate signing options and signing algorithm").
// A 2-year limit flagged a certificate Entra itself had just issued with
// zero abnormal configuration. There is no separate Microsoft guidance
// recommending a shorter SAML signing-certificate lifetime than this
// native ceiling, so the limit is set at 3 years: past this point a
// certificate can only exist because an admin manually extended it
// beyond what the platform itself offers.
const samlLongExpiryLimit = 3 * 365 * 24 * time.Hour // 3 years

type SAMLCertLongLifetimeDetector struct{ audit.BaseDetector }

func NewSAMLCertLongLifetimeDetector() *SAMLCertLongLifetimeDetector {
	return &SAMLCertLongLifetimeDetector{
		BaseDetector: audit.NewBaseDetector("SAML_CERTIFICATE_LONG_LIFETIME", audit.CategoryApplications),
	}
}

func (d *SAMLCertLongLifetimeDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	now := data.Now
	var affected []types.ServicePrincipal
	pairs := make([]string, 0)
	for i := range data.AzureServicePrincipals {
		sp := &data.AzureServicePrincipals[i]
		flagged := false
		for _, kc := range sp.KeyCredentials {
			if !isSigningCert(kc) {
				continue
			}
			if kc.EndDate.Sub(now) > samlLongExpiryLimit {
				if !flagged {
					affected = append(affected, *sp)
					flagged = true
				}
				pairs = append(pairs, fmt.Sprintf("sp=%s thumbprint=%s end=%s",
					sp.DisplayName, kc.Thumbprint, kc.EndDate.Format("2006-01-02")))
			}
		}
	}
	f := types.Finding{
		Type:     d.ID(),
		Severity: types.SeverityMedium,
		Category: string(d.Category()),
		Title:    "SAML signing certificate has excessive lifetime",
		Description: "One or more SAML token-signing certificates are valid for more than 3 years - beyond " +
			"the ceiling Microsoft Entra ID itself offers for a certificate created through the normal SAML " +
			"SSO configuration flow (3 years is both the default and the maximum selectable at creation time). " +
			"A certificate beyond that lifetime was manually extended past what the platform provides, and long-lived " +
			"signing credentials increase blast radius if compromised.",
		Count: len(affected),
		Details: map[string]interface{}{
			"recommendation": "Rotate certificates within the 3-year window Microsoft Entra ID provides by default.",
			"pairs":          pairs,
		},
	}
	if data.IncludeDetails && len(affected) > 0 {
		f.AffectedEntities = helpers.ToAffectedServicePrincipalEntities(affected)
	}
	return []types.Finding{f}
}

func init() {
	audit.MustRegister(NewSAMLCertLongLifetimeDetector())
}
