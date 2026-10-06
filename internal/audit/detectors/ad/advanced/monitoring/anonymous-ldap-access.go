package monitoring

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// AnonymousLdapAccessDetector detects if anonymous LDAP access is allowed
type AnonymousLdapAccessDetector struct {
	audit.BaseDetector
}

// NewAnonymousLdapAccessDetector creates a new detector
func NewAnonymousLdapAccessDetector() *AnonymousLdapAccessDetector {
	return &AnonymousLdapAccessDetector{
		BaseDetector: audit.NewBaseDetector("ANONYMOUS_LDAP_ACCESS", audit.CategoryAdvanced),
	}
}

// Detect executes the detection
func (d *AnonymousLdapAccessDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// This would be tested during the audit via separate anonymous bind attempt
	anonymousAccessAllowed := data.DomainInfo != nil && data.DomainInfo.AnonymousLDAPAllowed

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "Anonymous LDAP Access Allowed",
		Description: "LDAP server accepts anonymous binds. Attackers can enumerate AD objects (users, groups, computers) without valid credentials.",
		Count:       0,
	}

	if anonymousAccessAllowed {
		finding.Count = 1
		if data.IncludeDetails && data.DomainInfo != nil {
			finding.AffectedEntities = []types.AffectedEntity{types.DomainInfoToAffectedEntity(data.DomainInfo)}
			finding.Details = map[string]interface{}{
				"recommendation": "Configure 'Network security: LDAP client signing requirements' and restrict anonymous access via dsHeuristics.",
				"currentStatus":  "Anonymous bind allowed",
			}
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewAnonymousLdapAccessDetector())
}
