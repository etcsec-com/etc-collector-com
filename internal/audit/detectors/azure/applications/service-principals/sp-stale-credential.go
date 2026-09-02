package serviceprincipals

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
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
	oneYearAgo := now.AddDate(-1, 0, 0)

	for _, sp := range data.AzureServicePrincipals {
		hasStale := false
		for _, cred := range sp.PasswordCredentials {
			if cred.StartDate.Before(oneYearAgo) && cred.EndDate.After(now) {
				hasStale = true
				break
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
		Description: "Service principal credentials older than 1 year. Rotate credentials regularly. Implement regular credential rotation.",
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
