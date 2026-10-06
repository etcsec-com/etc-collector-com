package anssi

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// TestR29SIDFiltering_InboundOnlyTrustNotFlagged: ANSSI PA-099
// R24 (p.41) hardens OUTGOING extra-forest trusts only ("relations
// d'approbation SORTANTES extraforêt"). The previous implementation never
// read TrustDirection at all, so a purely inbound external trust without
// SIDFiltering was flagged even though R24 doesn't apply to it. This test
// would have FAILED against the old implementation (flagged regardless of
// direction) and passes now that inbound-only trusts are out of scope.
func TestR29SIDFiltering_InboundOnlyTrustNotFlagged(t *testing.T) {
	data := &audit.DetectorData{
		Trusts: []types.Trust{
			{TrustType: "External", TrustDirection: "Inbound", SIDFiltering: false},
		},
	}
	findings := NewR29TrustSIDFilteringDetector().Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 0 {
		t.Fatalf("expected an inbound-only external trust to be out of R24's outgoing-only scope, got %+v", findings)
	}
}

// TestR29SIDFiltering_ForestTrustExcluded: R24 hardens forest
// trusts via the ABSENCE of TREAT_AS_EXTERNAL, a distinct attribute not
// collected by the parser - checking SIDFiltering (QUARANTINED_DOMAIN) on a
// forest trust measures the wrong mechanism entirely. The previous
// implementation flagged any forest trust with SIDFiltering=false; this test
// would have FAILED against that (flagged) and passes now that forest
// trusts are excluded rather than checked against the wrong attribute.
func TestR29SIDFiltering_ForestTrustExcluded(t *testing.T) {
	data := &audit.DetectorData{
		Trusts: []types.Trust{
			{TrustType: "Forest", TrustDirection: "Outbound", SIDFiltering: false},
		},
	}
	findings := NewR29TrustSIDFilteringDetector().Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 0 {
		t.Fatalf("expected forest trusts to be excluded (wrong attribute for that trust type), got %+v", findings)
	}
}
