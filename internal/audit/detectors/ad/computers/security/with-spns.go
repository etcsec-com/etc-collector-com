package security

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// WithSPNsDetector checks for computers with SPNs (Kerberoastable)
type WithSPNsDetector struct {
	audit.BaseDetector
}

// NewWithSPNsDetector creates a new detector
func NewWithSPNsDetector() *WithSPNsDetector {
	return &WithSPNsDetector{
		BaseDetector: audit.NewBaseDetector("COMPUTER_WITH_SPNS", audit.CategoryComputers),
	}
}

// Detect executes the detection
func (d *WithSPNsDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.Computer

	for _, c := range data.Computers {
		if len(c.ServicePrincipalNames) > 0 {
			affected = append(affected, c)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "Computer with SPNs",
		Description: "Computer with Service Principal Names. Enables Kerberoasting attack against computer account.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedComputerEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewWithSPNsDetector())
}
