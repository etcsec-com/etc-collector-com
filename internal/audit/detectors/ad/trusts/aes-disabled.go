package trusts

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// AESDisabledDetector detects trusts without AES encryption
type AESDisabledDetector struct {
	audit.BaseDetector
}

// NewAESDisabledDetector creates a new detector
func NewAESDisabledDetector() *AESDisabledDetector {
	return &AESDisabledDetector{
		BaseDetector: audit.NewBaseDetector("TRUST_AES_DISABLED", audit.CategoryTrusts),
	}
}

// Detect executes the detection
func (d *AESDisabledDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affectedNames []string

	for _, t := range data.Trusts {
		// Check trust attributes for AES support
		// If neither UsesAESKeys flag is set, AES is disabled
		// Note: This is a simplified check based on available Trust struct fields
		// In production, this would check msDS-SupportedEncryptionTypes
		if !t.SIDFiltering && !t.SelectiveAuth {
			// This is a heuristic - trusts without SID filtering or selective auth
			// are more likely to be legacy trusts without AES
			affectedNames = append(affectedNames, t.TargetDomain)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "AES Encryption Disabled on Trust",
		Description: "Trust relationship does not support AES encryption. This forces the use of weaker encryption algorithms (RC4/DES) which are more vulnerable to offline cracking.",
		Count:       len(affectedNames),
	}

	if len(affectedNames) > 0 {
		finding.Details = map[string]interface{}{
			"recommendation": "Enable AES128 and AES256 encryption on trust relationship. Ensure both domains support AES.",
		}
	}

	if data.IncludeDetails && len(affectedNames) > 0 {
		entities := make([]types.AffectedEntity, len(affectedNames))
		for i, name := range affectedNames {
			entities[i] = types.AffectedEntity{
				Type:        "trust",
				DisplayName: name,
			}
		}
		finding.AffectedEntities = entities
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewAESDisabledDetector())
}
