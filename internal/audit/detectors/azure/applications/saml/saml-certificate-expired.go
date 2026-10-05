package saml

import (
	"context"
	"fmt"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

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

func init() {
	audit.MustRegister(NewSAMLCertExpiredDetector())
}
