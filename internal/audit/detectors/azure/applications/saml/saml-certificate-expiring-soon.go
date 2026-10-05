package saml

import (
	"context"
	"fmt"
	"time"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

const samlNearExpiryWindow = 30 * 24 * time.Hour // 30 days

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

func init() {
	audit.MustRegister(NewSAMLCertExpiringDetector())
}
