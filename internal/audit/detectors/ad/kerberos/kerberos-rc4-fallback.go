package kerberos

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// KerberosRc4FallbackDetector checks for accounts with RC4 fallback enabled
type KerberosRc4FallbackDetector struct {
	audit.BaseDetector
}

// NewKerberosRc4FallbackDetector creates a new detector
func NewKerberosRc4FallbackDetector() *KerberosRc4FallbackDetector {
	return &KerberosRc4FallbackDetector{
		BaseDetector: audit.NewBaseDetector("KERBEROS_RC4_FALLBACK", audit.CategoryKerberos),
	}
}

const rc4Support = 0x4 // RC4_HMAC_MD5

// Detect executes the detection
func (d *KerberosRc4FallbackDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.User

	for _, user := range data.Users {
		if user.Disabled {
			continue
		}

		encTypes := user.SupportedEncryptionTypes
		if encTypes == 0 {
			continue
		}

		// Has both AES and RC4 - RC4 should be disabled
		hasAes := (encTypes & aesSupport) != 0
		hasRc4 := (encTypes & rc4Support) != 0

		if hasAes && hasRc4 {
			affected = append(affected, user)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "RC4 Fallback Enabled",
		Description: "User accounts support both AES and RC4 encryption. RC4 fallback enables downgrade attacks even when AES is available.",
		Count:       len(affected),
		Details: map[string]interface{}{
			"recommendation": "Disable RC4 support when AES is available.",
		},
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewKerberosRc4FallbackDetector())
}
