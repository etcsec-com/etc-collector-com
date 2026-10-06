package kerberos

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// WeakEncryptionRC4Detector checks for accounts with RC4-only encryption
//
// This is the only WEAK_ENCRYPTION_* detector whose condition tests
// msDS-SupportedEncryptionTypes bit 0x4 (RC4) at all. WeakEncryptionDESDetector's
// attribute branch tests only bits 0x1/0x2 (desTypes, kerberos/weak-encryption-des.go)
// and never inspects bit 0x4, so an account configured with RC4 alone (no DES bit,
// no AES) - e.g. encTypes=4 - is invisible to WEAK_ENCRYPTION_DES and can only be
// caught here. Two other WEAK_ENCRYPTION_* detectors that used to overlap with this
// one and with WEAK_ENCRYPTION_DES were retired as always-subsumed by one or both of
// these two; within the WEAK_ENCRYPTION_* family, this detector's RC4-without-AES
// case has no possible sibling that would catch it.
//
// That exclusivity does not hold once KERBEROS_AES_DISABLED
// (kerberos/kerberos-aes-disabled.go, severity High) is considered. Its attribute
// branch is `!Disabled && encTypes != 0 && (encTypes & 0x18) == 0`, and this
// detector's own condition (`encTypes != 0 && (encTypes & 0x4) != 0 && (encTypes &
// 0x18) == 0`) implies that branch for every possible encTypes value, negative
// values included: both conditions gate on the identical `!= 0` test (this
// detector's own "encTypes == 0" skip above is exactly that test), and the no-AES
// test is identical bit for bit regardless of sign, since a bitwise AND on a
// signed integer operates on its two's-complement bits unchanged. So for every
// account where Disabled is false, KERBEROS_AES_DISABLED already reports it (at
// High, where this detector reports the same account at Medium). The one case this
// detector catches that nothing else does is RC4-without-AES on a DISABLED account,
// and that is only because of the state-filter gap described next:
// KERBEROS_AES_DISABLED skips Disabled accounts before evaluating either of its
// branches, and this detector applies no such filter.
//
// Known gap, not fixed here: unlike WeakEncryptionDESDetector this detector does not
// exclude Disabled accounts, even though the same [MS-KILE] AS-REQ argument documented
// on WeakEncryptionDESDetector applies identically to the RC4 condition (a disabled
// account cannot reach the initial exchange where RC4-without-AES would matter either).
// Filtering it correctly would need a companion WEAK_ENCRYPTION_RC4_ON_DISABLED_ACCOUNT
// detector (its own file, per this package's one-detector-per-file rule) rather than
// silently dropping the disabled population, so it is left as a follow-up rather than
// half-fixed here.
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
