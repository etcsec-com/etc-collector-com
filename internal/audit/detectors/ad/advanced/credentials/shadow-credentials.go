package credentials

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// ShadowCredentialsDetector detects Shadow Credentials attack vectors
type ShadowCredentialsDetector struct {
	audit.BaseDetector
}

// NewShadowCredentialsDetector creates a new detector
func NewShadowCredentialsDetector() *ShadowCredentialsDetector {
	return &ShadowCredentialsDetector{
		BaseDetector: audit.NewBaseDetector("SHADOW_CREDENTIALS", audit.CategoryAdvanced),
	}
}

// Detect executes the detection
func (d *ShadowCredentialsDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.User

	for _, u := range data.Users {
		// Check msDS-KeyCredentialLink attribute
		if len(u.KeyCredentialLink) > 0 {
			affected = append(affected, u)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityCritical,
		Category:    string(d.Category()),
		Title:       "Shadow Credentials",
		Description: "msDS-KeyCredentialLink attribute configured. Allows Kerberos authentication bypass by adding arbitrary public keys.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewShadowCredentialsDetector())
}
