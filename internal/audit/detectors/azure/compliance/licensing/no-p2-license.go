package licensing

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

const (
	AZ_NO_P2_LICENSE = "AZ_NO_P2_LICENSE"
)

type NoP2LicenseDetector struct {
	audit.BaseDetector
}

func NewNoP2LicenseDetector() *NoP2LicenseDetector {
	return &NoP2LicenseDetector{
		BaseDetector: audit.NewBaseDetector(
			AZ_NO_P2_LICENSE,
			audit.CategoryAzureCompliance,
		),
	}
}

// B_158/T_058 — used to fire unconditionally on every tenant regardless of
// license, contradicting data.AzureLicenseTier on the same audit whenever P2
// was actually active. AzureLicenseTier is always populated by
// collectAzureData ("free" is the safe default on a collection failure, not
// an "unknown" sentinel), so this reads the one real signal and stays silent
// once P2 is confirmed.
func (d *NoP2LicenseDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	if data.AzureLicenseTier == "p2" {
		return nil
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "Azure AD P2 License Not Active",
		Description: "Advisory: Key security features (PIM, Identity Protection, Access Reviews) require Azure AD P2 licensing.",
		Count:       1,
	}

	if data.IncludeDetails {
		finding.AffectedEntities = []types.AffectedEntity{
			{
				Type:        "tenant",
				DN:          "tenant",
				Name:        "Azure AD Tenant",
				Description: "Detected license tier: " + data.AzureLicenseTier,
			},
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewNoP2LicenseDetector())
}
