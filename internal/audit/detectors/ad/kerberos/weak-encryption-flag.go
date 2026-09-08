package kerberos

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// WeakEncryptionFlagDetector checks for accounts with USE_DES_KEY_ONLY flag
type WeakEncryptionFlagDetector struct {
	audit.BaseDetector
}

// NewWeakEncryptionFlagDetector creates a new detector
func NewWeakEncryptionFlagDetector() *WeakEncryptionFlagDetector {
	return &WeakEncryptionFlagDetector{
		BaseDetector: audit.NewBaseDetector("WEAK_ENCRYPTION_FLAG", audit.CategoryKerberos),
	}
}

// Detect executes the detection
func (d *WeakEncryptionFlagDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.User

	for _, user := range data.Users {
		// Check for USE_DES_KEY_ONLY flag (0x200000)
		if (user.UserAccountControl & uacUseDESKeyOnly) != 0 {
			affected = append(affected, user)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "Weak Encryption Flag",
		Description: "User accounts with USE_DES_KEY_ONLY flag enabled (UAC 0x200000). Forces weak DES encryption.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewWeakEncryptionFlagDetector())
}
