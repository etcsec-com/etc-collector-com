package security

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// WeakEncryptionDetector checks for computers with weak encryption types
type WeakEncryptionDetector struct {
	audit.BaseDetector
}

// NewWeakEncryptionDetector creates a new detector
func NewWeakEncryptionDetector() *WeakEncryptionDetector {
	return &WeakEncryptionDetector{
		BaseDetector: audit.NewBaseDetector("COMPUTER_WEAK_ENCRYPTION", audit.CategoryComputers),
	}
}

// Detect executes the detection
func (d *WeakEncryptionDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// Encryption type flags:
	// 0x1 = DES_CBC_CRC
	// 0x2 = DES_CBC_MD5
	// 0x4 = RC4_HMAC
	// 0x8 = AES128
	// 0x10 = AES256
	const aesMask = 0x18 // AES128 | AES256
	const weakMask = 0x7 // DES_CBC_CRC | DES_CBC_MD5 | RC4_HMAC

	var affected []types.Computer

	for _, c := range data.Computers {
		encTypes := c.SupportedEncryptionTypes
		if encTypes == 0 {
			continue
		}

		// Check if only DES/RC4 (no AES support)
		hasAES := (encTypes & aesMask) != 0
		hasWeak := (encTypes & weakMask) != 0

		if !hasAES && hasWeak {
			affected = append(affected, c)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "Computer Weak Encryption",
		Description: "Computer with weak encryption types (DES/RC4 only). Vulnerable to Kerberos downgrade attacks.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedComputerEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewWeakEncryptionDetector())
}
