package anssi

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// TestR33ExternalTrustPermissive_EitherProtectionIsSufficient:
// R24's own text frames R25+ (Selective Authentication) as a compensating
// fallback "à défaut" of R24 (SID filtering) - either protection present is
// an acceptable mitigation, not a mandatory AND of both. The previous
// implementation flagged a trust as permissive if EITHER was missing
// (requiring BOTH to be compliant), stricter than the source. This test
// would have FAILED against the old OR-trigger (SIDFiltering off but
// SelectiveAuth on → still flagged) and passes now that having one
// protection is enough.
func TestR33ExternalTrustPermissive_EitherProtectionIsSufficient(t *testing.T) {
	data := &audit.DetectorData{
		Trusts: []types.Trust{
			{TrustType: "External", TrustDirection: "Outbound", SelectiveAuth: true, SIDFiltering: false},
		},
	}
	findings := NewR33ExternalTrustPermissiveDetector().Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 0 {
		t.Fatalf("expected a trust with Selective Auth (but not SID filtering) to be compliant per R24's own fallback framing, got %+v", findings)
	}
}

// TestR33ExternalTrustPermissive_BothMissingIsFlagged confirms the detector
// still fires when NEITHER protection is present.
func TestR33ExternalTrustPermissive_BothMissingIsFlagged(t *testing.T) {
	data := &audit.DetectorData{
		Trusts: []types.Trust{
			{TrustType: "External", TrustDirection: "Outbound", SelectiveAuth: false, SIDFiltering: false},
		},
	}
	findings := NewR33ExternalTrustPermissiveDetector().Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 1 {
		t.Fatalf("expected a trust with neither protection to be flagged, got %+v", findings)
	}
}
