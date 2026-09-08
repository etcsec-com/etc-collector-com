package password

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// ReversibleEncryptionDetector detects accounts with reversible encryption
type ReversibleEncryptionDetector struct {
	audit.BaseDetector
}

// NewReversibleEncryptionDetector creates a new detector
func NewReversibleEncryptionDetector() *ReversibleEncryptionDetector {
	return &ReversibleEncryptionDetector{
		BaseDetector: audit.NewBaseDetector("REVERSIBLE_ENCRYPTION", audit.CategoryPassword),
	}
}

// Detect executes the detection
func (d *ReversibleEncryptionDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// ENCRYPTED_TEXT_PASSWORD_ALLOWED flag (UAC 0x80)
	const uacReversibleEncryption = 0x80

	var affected []types.User

	for _, u := range data.Users {
		// Check UAC flag for ENCRYPTED_TEXT_PASSWORD_ALLOWED
		if (u.UserAccountControl & uacReversibleEncryption) != 0 {
			affected = append(affected, u)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityCritical,
		Category:    string(d.Category()),
		Title:       "Reversible Encryption",
		Description: "Passwords stored with reversible encryption (UAC flag 0x80). Equivalent to storing passwords in cleartext.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewReversibleEncryptionDetector())
}
