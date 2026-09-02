package other

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// AltSecurityIdentitiesDetector detects privileged accounts with altSecurityIdentities configured
type AltSecurityIdentitiesDetector struct {
	audit.BaseDetector
}

// NewAltSecurityIdentitiesDetector creates a new detector
func NewAltSecurityIdentitiesDetector() *AltSecurityIdentitiesDetector {
	return &AltSecurityIdentitiesDetector{
		BaseDetector: audit.NewBaseDetector("ALT_SECURITY_IDENTITIES", audit.CategoryAdvanced),
	}
}

// Detect executes the detection
func (d *AltSecurityIdentitiesDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.User

	for _, user := range data.Users {
		if len(user.AltSecurityIdentities) == 0 {
			continue
		}

		if helpers.IsInAnyGroup(user.MemberOf, helpers.AdminGroups) {
			affected = append(affected, user)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "Privileged Accounts with altSecurityIdentities Configured",
		Description: "Privileged accounts have the altSecurityIdentities attribute configured, which maps external credentials (certificates, Kerberos principals) to AD accounts. This can be exploited for certificate-based impersonation attacks.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewAltSecurityIdentitiesDetector())
}
