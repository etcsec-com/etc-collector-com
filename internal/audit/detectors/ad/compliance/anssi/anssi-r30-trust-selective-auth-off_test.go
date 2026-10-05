package anssi

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// TestR30SelectiveAuth_InboundOnlyTrustNotFlagged: ANSSI PA-099
// R25+ (p.42) also scopes to outgoing extra-forest trusts only. This test
// would have FAILED against the old direction-blind implementation and
// passes now that inbound-only trusts are excluded.
func TestR30SelectiveAuth_InboundOnlyTrustNotFlagged(t *testing.T) {
	data := &audit.DetectorData{
		Trusts: []types.Trust{
			{TrustType: "Forest", TrustDirection: "Inbound", SelectiveAuth: false},
		},
	}
	findings := NewR30TrustSelectiveAuthDetector().Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 0 {
		t.Fatalf("expected an inbound-only forest trust to be out of R25+'s outgoing-only scope, got %+v", findings)
	}
}
