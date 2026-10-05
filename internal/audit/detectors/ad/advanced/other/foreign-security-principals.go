package other

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// ForeignSecurityPrincipalsDetector detects foreign security principals.
//
// Source check: DomainInfo.ForeignSecurityPrincipalsCount (populated by the
// LDAP provider from a raw count of objectClass=foreignSecurityPrincipal
// under CN=ForeignSecurityPrincipals) counts every FSP placeholder, and
// Windows creates one not only for a real principal from a trusted external
// domain/forest, but also whenever a well-known SID (Everyone S-1-1-0,
// Authenticated Users S-1-5-11, Anonymous Logon S-1-5-7, etc.) is added to
// an ACL anywhere in the domain - see Microsoft Learn, "Foreign Security
// Principals and Well-Known SIDS, a.k.a. the curly red arrow problem"
// (learn.microsoft.com/en-us/archive/blogs/389thoughts/...). The collector
// only exposes a count (no per-object SID), so this detector cannot
// distinguish that by-design noise from a real cross-forest exposure -
// the Description below says so, instead of implying every FSP is a trust
// finding.
type ForeignSecurityPrincipalsDetector struct {
	audit.BaseDetector
}

// NewForeignSecurityPrincipalsDetector creates a new detector
func NewForeignSecurityPrincipalsDetector() *ForeignSecurityPrincipalsDetector {
	return &ForeignSecurityPrincipalsDetector{
		BaseDetector: audit.NewBaseDetector("FOREIGN_SECURITY_PRINCIPALS", audit.CategoryAdvanced),
	}
}

// Detect executes the detection
func (d *ForeignSecurityPrincipalsDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// Foreign security principals would be populated from a separate LDAP query
	// For now, count is based on DomainInfo if available
	count := 0
	if data.DomainInfo != nil {
		count = data.DomainInfo.ForeignSecurityPrincipalsCount
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "Foreign Security Principals",
		Description: "Foreign security principal (FSP) placeholder objects exist in the domain. Some may represent real principals from a trusted external domain/forest (potential cross-forest exposure); Windows also creates the same kind of placeholder for well-known SIDs (Everyone, Authenticated Users, Anonymous Logon, ...) referenced in any ACL, which is normal and not itself a trust exposure. This count cannot distinguish the two - manually review each FSP's SID before treating it as a foreign-forest risk.",
		Count:       count,
	}

	if count > 0 {
		finding.Details = map[string]interface{}{
			"caveat": "Count includes FSP placeholders auto-created for well-known SIDs (Everyone, Authenticated Users, etc.) referenced in ACLs, which are not cross-forest principals. The collector does not expose per-object SIDs, so this figure cannot be narrowed further automatically.",
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewForeignSecurityPrincipalsDetector())
}
