package kerberos

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// WeakEncryptionDESDetector checks for accounts with DES encryption enabled
type WeakEncryptionDESDetector struct {
	audit.BaseDetector
}

// NewWeakEncryptionDESDetector creates a new detector
func NewWeakEncryptionDESDetector() *WeakEncryptionDESDetector {
	return &WeakEncryptionDESDetector{
		BaseDetector: audit.NewBaseDetector("WEAK_ENCRYPTION_DES", audit.CategoryKerberos),
	}
}

const desTypes = 0x3 // DES_CBC_CRC (0x1) | DES_CBC_MD5 (0x2)

// Detect executes the detection
func (d *WeakEncryptionDESDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.User

	for _, user := range data.Users {
		// Check UAC flag USE_DES_KEY_ONLY
		if (user.UserAccountControl & uacUseDESKeyOnly) != 0 {
			affected = append(affected, user)
			continue
		}

		// Check msDS-SupportedEncryptionTypes for DES support
		if user.SupportedEncryptionTypes > 0 && (user.SupportedEncryptionTypes&desTypes) != 0 {
			affected = append(affected, user)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "Weak DES Encryption",
		Description: "User accounts with DES encryption algorithms enabled (UAC 0x200000 or msDS-SupportedEncryptionTypes). DES is cryptographically broken.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewWeakEncryptionDESDetector())
}
