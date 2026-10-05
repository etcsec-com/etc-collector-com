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

	// Trust.AESEnabled is populated from msDS-SupportedEncryptionTypes
	// (internal/providers/ldap/client.go trustEncryptionFlags).
	// Before that field was read, this detector used a heuristic based on
	// SIDFiltering/SelectiveAuth - attributes that have nothing to do with
	// encryption - which meant a correctly SID-filtered, non-selective-auth
	// trust with AES enabled was flagged "AES Encryption Disabled" while a
	// trust with the opposite (no filtering, AES actually disabled) could
	// pass.
	for _, t := range data.Trusts {
		if !t.AESEnabled {
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
				Type: "trust",
				Name: name,
			}
		}
		finding.AffectedEntities = entities
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewAESDisabledDetector())
}
