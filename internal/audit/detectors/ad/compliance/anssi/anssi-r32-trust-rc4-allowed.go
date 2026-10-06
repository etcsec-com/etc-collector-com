package anssi

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// --- R32: Trust must support AES (no RC4 cross-realm) ---

type R32TrustRC4Detector struct{ audit.BaseDetector }

func NewR32TrustRC4Detector() *R32TrustRC4Detector {
	return &R32TrustRC4Detector{BaseDetector: audit.NewBaseDetector("ANSSI_R32_TRUST_RC4_ALLOWED", audit.CategoryCompliance)}
}
func (d *R32TrustRC4Detector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	count := 0
	for _, t := range data.Trusts {
		// AES not enabled OR RC4 explicitly enabled = downgrade risk.
		if !t.AESEnabled || t.RC4Enabled {
			count++
		}
	}
	return wrapFinding(d, "ANSSI R32 - Trust autorisant RC4 (pas AES-only)",
		"ANSSI R32 requires AES-only on trust referrals (msDS-SupportedEncryptionTypes flag). RC4 cross-realm tickets are kerberoastable and downgrade attacks remain possible.",
		types.SeverityMedium, count, nil)
}

func init() {
	audit.MustRegister(NewR32TrustRC4Detector())
}
