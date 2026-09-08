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
	var affectedNames []string

	// Trust.AESEnabled/RC4Enabled are populated from
	// msDS-SupportedEncryptionTypes (internal/providers/ldap/client.go
	// trustEncryptionFlags). RC4-only means the trust supports RC4
	// and does NOT support AES - distinct from ANSSI_R32
	// (!AESEnabled || RC4Enabled), which also flags trusts where the
	// attribute is simply unset (both false). Requiring RC4Enabled here
	// avoids firing on trusts where the encryption type just isn't
	// reported.
	for _, t := range data.Trusts {
		if t.RC4Enabled && !t.AESEnabled {
			name := t.TargetDomain
			if name == "" {
				name = t.Name
			}
			affectedNames = append(affectedNames, name)
		}
	}

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
