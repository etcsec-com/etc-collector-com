package other

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// ForeignSecurityPrincipalsDetector detects foreign security principals
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
		Description: "Foreign security principals from external forests. Potential for cross-forest privilege escalation.",
		Count:       count,
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewForeignSecurityPrincipalsDetector())
}
