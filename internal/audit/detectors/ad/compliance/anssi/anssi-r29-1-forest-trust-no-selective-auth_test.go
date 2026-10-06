package anssi

import (
	"context"
	"strings"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// --- R29.1 (real control: R25+, outgoing trusts only) ---
//
// The previous implementation counted every non-selective-auth forest
// trust regardless of direction. R25+'s text is explicitly scoped to
// outgoing ("sortantes") trusts. This test would have FAILED against the
// old implementation (an inbound-only forest trust would have been
// counted) and passes against the fix (inbound-only trusts are excluded).
func TestR291ForestTrustNoSelAuth_InboundOnly_NotFlagged(t *testing.T) {
	data := &audit.DetectorData{
		Trusts: []types.Trust{
			{TargetDomain: "inbound.example.com", TrustType: "Forest", TrustDirection: "Inbound", SelectiveAuth: false},
		},
	}
	d := NewR291ForestTrustNoSelAuthDetector()
	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 0 {
		t.Fatalf("expected inbound-only forest trust to be out of R25+'s scope, got %+v", findings)
	}
}

func TestR291ForestTrustNoSelAuth_Outbound_Flagged(t *testing.T) {
	data := &audit.DetectorData{
		Trusts: []types.Trust{
			{TargetDomain: "outbound.example.com", TrustType: "Forest", TrustDirection: "Outbound", SelectiveAuth: false},
		},
	}
	d := NewR291ForestTrustNoSelAuthDetector()
	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 1 {
		t.Fatalf("expected outbound forest trust without selective auth to be flagged, got %+v", findings)
	}
	if strings.Contains(findings[0].Title, "R29.1") || strings.Contains(findings[0].Description, "R29.1") {
		t.Errorf("finding should not cite the nonexistent PA-099 R29.1 sub-reco, got title=%q desc=%q", findings[0].Title, findings[0].Description)
	}
}

func TestR291ForestTrustNoSelAuth_BidirectionalWithSelectiveAuth_NoFinding(t *testing.T) {
	data := &audit.DetectorData{
		Trusts: []types.Trust{
			{TargetDomain: "both.example.com", TrustType: "Forest", TrustDirection: "Bidirectional", SelectiveAuth: true},
		},
	}
	d := NewR291ForestTrustNoSelAuthDetector()
	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 0 {
		t.Fatalf("expected compliant bidirectional trust to be clean, got %+v", findings)
	}
}
