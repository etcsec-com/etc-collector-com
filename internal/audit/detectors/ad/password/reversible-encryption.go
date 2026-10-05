package password

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// ReversibleEncryptionDetector detects accounts whose password is persisted
// with reversible encryption (UAC ENCRYPTED_TEXT_PASSWORD_ALLOWED, 0x80).
//
// Deliberately NOT split by account state, unlike the sibling detectors in
// this package (see NotRequiredDetector, NeverExpiresDetector). Their risk
// requires the account to authenticate, so a disabled account is genuinely
// dormant. This flag's risk is that AD persists the password in a recoverable
// form at rest (see ms-DS-User-Encrypted-Text-Password-Allowed and
// ADS_UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED in [MS-ADTS]): disabling the account
// does not clear or re-encrypt that stored value, so the exposure is identical
// whether the account is enabled or disabled. Splitting on account state here
// would only add a catalog entry without changing what is actually at risk.
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
	var affected []types.User

	for _, u := range data.Users {
		if (u.UserAccountControl & types.UACEncryptedTextPasswordAllowed) != 0 {
			affected = append(affected, u)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityCritical,
		Category:    string(d.Category()),
		Title:       "Reversible Encryption",
		Description: "Passwords stored with reversible encryption (UAC flag 0x80, ENCRYPTED_TEXT_PASSWORD_ALLOWED). Equivalent to storing the password in cleartext in the directory. The exposure is at rest, not tied to authentication: disabling the account does not clear the stored reversible secret, and a re-enable restores its full usefulness immediately.",
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
