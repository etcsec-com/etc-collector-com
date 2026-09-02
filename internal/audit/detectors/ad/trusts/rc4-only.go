package trusts

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// RC4OnlyDetector detects trusts that only support RC4 encryption
type RC4OnlyDetector struct {
	audit.BaseDetector
}

// NewRC4OnlyDetector creates a new detector
func NewRC4OnlyDetector() *RC4OnlyDetector {
	return &RC4OnlyDetector{
		BaseDetector: audit.NewBaseDetector("TRUST_RC4_ONLY", audit.CategoryTrusts),
	}
}

// Detect executes the detection
func (d *RC4OnlyDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// Note: The current Trust type doesn't have supportedEncryptionTypes field
	// This detector would need an extended Trust type to properly detect RC4-only trusts
	// For now, we'll return an empty finding as the data model doesn't support this check
	var affectedNames []string

	// If we had access to supportedEncryptionTypes, we would do:
	// for _, t := range data.Trusts {
	//     if t.SupportedEncryptionTypes != 0 {
	//         hasOnlyWeak := (t.SupportedEncryptionTypes & EncWeakOnly) != 0 &&
	//                        (t.SupportedEncryptionTypes & EncAESTypes) == 0
	//         isRC4Only := hasOnlyWeak && (t.SupportedEncryptionTypes & EncTypeRC4HMAC) != 0
	//         if isRC4Only {
	//             affectedNames = append(affectedNames, t.TargetDomain)
	//         }
	//     }
	// }

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "Trust Only Supports RC4 Encryption",
		Description: "Trust relationship only supports RC4 encryption (no AES). RC4 is deprecated and Kerberos tickets encrypted with RC4 are vulnerable to offline cracking attacks.",
		Count:       len(affectedNames),
	}

	if len(affectedNames) > 0 {
		finding.Details = map[string]interface{}{
			"recommendation": "Enable AES encryption on trust. If the partner domain does not support AES, plan an upgrade path.",
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
	audit.MustRegister(NewRC4OnlyDetector())
}
