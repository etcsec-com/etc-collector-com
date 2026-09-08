package kerberos

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// WeakEncryptionRC4Detector checks for accounts with RC4-only encryption
type WeakEncryptionRC4Detector struct {
	audit.BaseDetector
}

// NewWeakEncryptionRC4Detector creates a new detector
func NewWeakEncryptionRC4Detector() *WeakEncryptionRC4Detector {
	return &WeakEncryptionRC4Detector{
		BaseDetector: audit.NewBaseDetector("WEAK_ENCRYPTION_RC4", audit.CategoryKerberos),
	}
}

// Detect executes the detection
func (d *WeakEncryptionRC4Detector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.User

	for _, user := range data.Users {
		encTypes := user.SupportedEncryptionTypes
		if encTypes == 0 {
			continue
		}

		// RC4 enabled (0x4) but no AES (0x18)
		hasRc4 := (encTypes & 0x4) != 0
		hasAes := (encTypes & 0x18) != 0

		if hasRc4 && !hasAes {
			affected = append(affected, user)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "Weak RC4 Encryption",
		Description: "User accounts supporting RC4 encryption without AES. RC4 is deprecated and vulnerable to attacks.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewWeakEncryptionRC4Detector())
}
