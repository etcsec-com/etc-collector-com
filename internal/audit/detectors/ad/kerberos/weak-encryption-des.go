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
//
// Disabled accounts are excluded here on purpose, on BOTH branches below, on
// the same [MS-KILE] "Check Account Policy for Every TGT Request" grounds as
// CONSTRAINED_DELEGATION: obtaining an initial TGT (AS-REQ) for this account -
// the step both branches need before either encryption type can matter at all
// - requires the account's own valid AS-REQ, and a disabled account gets
// KDC_ERR_CLIENT_REVOKED there regardless of which of the two conditions below
// it carries. It is not dropped from the audit -
// WeakEncryptionDESOnDisabledAccountDetector reports it at Low, since the
// configuration persists and would matter again the moment the account is
// re-enabled.
//
// Neither branch is a live "DES protects this account's tickets today" risk
// on a default-configured modern KDC (this catalogue's lab runs Server 2022):
// per [MS-KILE] TGS Exchange, "DES MUST NOT be used to protect the service
// ticket. If DES is the only configured etype, the KDC MUST return
// KDC_ERR_ETYPE_NOTSUPP" - unconditionally, independent of account state. Per
// [MS-KILE] AS Exchange, a DES pre-authentication attempt is rejected the same
// way UNLESS UseDESOnly is set on the account, which is exactly the UAC-bit
// branch below - that branch alone can still complete a DES-encrypted initial
// exchange, exposing that DES-derived key to offline cracking, before the
// resulting ticket becomes useless at the very next request. The attribute
// branch alone (DES bits set without the UAC bit) cannot get that far: AS
// Exchange rejects its DES pre-auth outright, so on this lab's two real
// carriers (both have RC4 alongside the DES bits) the condition is
// configured but inert. High reflects the UAC-bit branch's real exposure;
// the attribute branch alone is a weaker case flagged for its own ticket, not
// changed here.
func (d *WeakEncryptionDESDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.User

	for _, user := range data.Users {
		if user.Disabled {
			continue
		}

		// Check UAC flag USE_DES_KEY_ONLY
		if (user.UserAccountControl & uacUseDESKeyOnly) != 0 {
			affected = append(affected, user)
			continue
		}

		// Check msDS-SupportedEncryptionTypes for DES support. No `> 0` guard:
		// AD accepts a negative value here (bit 31 set), and the DES bits
		// 0x3 checked by the mask below survive two's-complement sign
		// extension untouched - a `> 0` guard would silently exclude them.
		if (user.SupportedEncryptionTypes & desTypes) != 0 {
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
