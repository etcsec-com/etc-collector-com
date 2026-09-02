package certificates

import (
	"context"
	"fmt"
	"time"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// CBAPersistenceDetector flags app registrations and service principals that have
// active (non-expired) certificate credentials. Certificate-based auth provides a
// persistence vector that survives password resets. Matches Purple Knight SI000144.
type CBAPersistenceDetector struct {
	audit.BaseDetector
}

func NewCBAPersistenceDetector() *CBAPersistenceDetector {
	return &CBAPersistenceDetector{
		BaseDetector: audit.NewBaseDetector("CBA_CERTIFICATES_ACTIVE", audit.CategoryApplications),
	}
}

func (d *CBAPersistenceDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	now := data.Now

	var affectedApps []types.AppRegistration
	var affectedSPs []types.ServicePrincipal
	pairs := make([]string, 0)

	for i := range data.AzureAppRegistrations {
		app := &data.AzureAppRegistrations[i]
		if hasActiveCert(app.KeyCredentials, now) {
			affectedApps = append(affectedApps, *app)
			for _, c := range app.KeyCredentials {
				if c.Type == "certificate" && c.EndDate.After(now) {
					pairs = append(pairs, fmt.Sprintf("app=%s thumbprint=%s expires=%s",
						app.DisplayName, c.Thumbprint, c.EndDate.Format(time.RFC3339)))
				}
			}
		}
	}

	for i := range data.AzureServicePrincipals {
		sp := &data.AzureServicePrincipals[i]
		if hasActiveCert(sp.KeyCredentials, now) {
			affectedSPs = append(affectedSPs, *sp)
			for _, c := range sp.KeyCredentials {
				if c.Type == "certificate" && c.EndDate.After(now) {
					pairs = append(pairs, fmt.Sprintf("sp=%s thumbprint=%s expires=%s",
						sp.DisplayName, c.Thumbprint, c.EndDate.Format(time.RFC3339)))
				}
			}
		}
	}

	count := len(affectedApps) + len(affectedSPs)

	finding := types.Finding{
		Type:     d.ID(),
		Severity: types.SeverityHigh,
		Category: string(d.Category()),
		Title:    "Active certificate-based authentication on applications",
		Description: "One or more app registrations or service principals have active (non-expired) " +
			"certificate credentials. Certificate-based authentication provides a persistence vector " +
			"that survives password resets. Review each certificate's ownership and necessity.",
		Count: count,
		Details: map[string]interface{}{
			"recommendation": "Inventory each active certificate. Remove unused ones and ensure rotation policies are in place.",
			"pairs":          pairs,
		},
	}

	if data.IncludeDetails && count > 0 {
		entities := helpers.ToAffectedAppEntities(affectedApps)
		entities = append(entities, helpers.ToAffectedServicePrincipalEntities(affectedSPs)...)
		finding.AffectedEntities = entities
	}

	return []types.Finding{finding}
}

func hasActiveCert(creds []types.AppCredential, now time.Time) bool {
	for _, c := range creds {
		if c.Type == "certificate" && c.EndDate.After(now) {
			return true
		}
	}
	return false
}

func init() {
	audit.MustRegister(NewCBAPersistenceDetector())
}
