package serviceaccounts

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// WeakEncryptionDetector detects service accounts with weak encryption
type WeakEncryptionDetector struct {
	audit.BaseDetector
}

// NewWeakEncryptionDetector creates a new detector
func NewWeakEncryptionDetector() *WeakEncryptionDetector {
	return &WeakEncryptionDetector{
		BaseDetector: audit.NewBaseDetector("SERVICE_ACCOUNT_WEAK_ENCRYPTION", audit.CategoryAccounts),
	}
}

// Detect executes the detection
func (d *WeakEncryptionDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.User

	// msDS-SupportedEncryptionTypes bit flags
	// 0x1 = DES-CBC-CRC, 0x2 = DES-CBC-MD5 (both weak)
	// 0x4 = RC4-HMAC (weak), 0x8 = AES128, 0x10 = AES256
	const weakMask = 0x7 // DES + RC4
	const aesMask = 0x18 // AES128 + AES256

	for _, u := range data.Users {
		// Must be a service account
		if !isServiceAccount(u) {
			continue
		}
		// Must be enabled
		if u.Disabled {
			continue
		}

		encTypes := u.SupportedEncryptionTypes
		if encTypes == 0 {
			continue
		}

		// Check if only weak encryption types are enabled (DES or RC4 only, no AES)
		hasOnlyWeak := (encTypes&weakMask) != 0 && (encTypes&aesMask) == 0
		if hasOnlyWeak {
			affected = append(affected, u)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "Service Account Using Weak Kerberos Encryption",
		Description: "Service accounts configured to use only weak Kerberos encryption (DES/RC4) without AES. Makes offline cracking easier.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
		finding.Details = map[string]interface{}{
			"recommendation": "Enable AES128 and AES256 encryption for all service accounts.",
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewWeakEncryptionDetector())
}
