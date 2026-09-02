package saml

import (
	"context"
	"fmt"
	"time"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// SAML signing certificate detectors audit token-signing credentials on service
// principals. Matches Purple Knight SI000117.
//
// The detectors read existing ServicePrincipal.KeyCredentials whose Usage is
// "Sign" (or empty) — those are the token-signing certificates used for SAML
// SSO. No separate type or new API call is required; the data is already
// fetched by the Azure provider and now includes Thumbprint + Usage.

const (
	samlNearExpiryWindow = 30 * 24 * time.Hour      // 30 days
	samlLongExpiryLimit  = 2 * 365 * 24 * time.Hour // 2 years
)

// isSigningCert returns true when the credential is a token-signing certificate
// eligible for the SAML checks.
func isSigningCert(kc types.AppCredential) bool {
	if kc.Type != "certificate" {
		return false
	}
	// Empty Usage is treated as potentially signing (defensive default).
	return kc.Usage == "" || kc.Usage == "Sign" || kc.Usage == "Verify"
}

// ---- expired ----

type SAMLCertExpiredDetector struct{ audit.BaseDetector }

func NewSAMLCertExpiredDetector() *SAMLCertExpiredDetector {
	return &SAMLCertExpiredDetector{
		BaseDetector: audit.NewBaseDetector("SAML_CERTIFICATE_EXPIRED", audit.CategoryApplications),
	}
}

func (d *SAMLCertExpiredDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
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
			if kc.EndDate.Before(now) {
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
		Severity: types.SeverityCritical,
		Category: string(d.Category()),
		Title:    "SAML signing certificate expired",
		Description: "One or more service principals have an expired SAML SSO token-signing " +
			"certificate. Federated sign-in through this SP will fail until the certificate is rotated.",
		Count: len(affected),
		Details: map[string]interface{}{
			"recommendation": "Rotate the token-signing certificate immediately.",
			"pairs":          pairs,
		},
	}
	if data.IncludeDetails && len(affected) > 0 {
		f.AffectedEntities = helpers.ToAffectedServicePrincipalEntities(affected)
	}
	return []types.Finding{f}
}

// ---- expiring soon ----

type SAMLCertExpiringDetector struct{ audit.BaseDetector }

func NewSAMLCertExpiringDetector() *SAMLCertExpiringDetector {
	return &SAMLCertExpiringDetector{
		BaseDetector: audit.NewBaseDetector("SAML_CERTIFICATE_EXPIRING_SOON", audit.CategoryApplications),
	}
}

func (d *SAMLCertExpiringDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
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
			if kc.EndDate.After(now) && kc.EndDate.Sub(now) < samlNearExpiryWindow {
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
		Severity: types.SeverityHigh,
		Category: string(d.Category()),
		Title:    "SAML signing certificate expiring within 30 days",
		Description: "One or more SAML token-signing certificates will expire within 30 days. " +
			"Rotate and coordinate metadata updates with the relying party before expiry.",
		Count: len(affected),
		Details: map[string]interface{}{
			"recommendation": "Schedule rotation and update the relying party metadata.",
			"pairs":          pairs,
		},
	}
	if data.IncludeDetails && len(affected) > 0 {
		f.AffectedEntities = helpers.ToAffectedServicePrincipalEntities(affected)
	}
	return []types.Finding{f}
}

// ---- long lifetime ----

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
		Description: "One or more SAML token-signing certificates are valid for more than 2 years. " +
			"Long-lived signing credentials increase blast radius if compromised.",
		Count: len(affected),
		Details: map[string]interface{}{
			"recommendation": "Rotate certificates at least every 1–2 years and align with tenant rotation policy.",
			"pairs":          pairs,
		},
	}
	if data.IncludeDetails && len(affected) > 0 {
		f.AffectedEntities = helpers.ToAffectedServicePrincipalEntities(affected)
	}
	return []types.Finding{f}
}

func init() {
	audit.MustRegister(NewSAMLCertExpiredDetector())
	audit.MustRegister(NewSAMLCertExpiringDetector())
	audit.MustRegister(NewSAMLCertLongLifetimeDetector())
}
