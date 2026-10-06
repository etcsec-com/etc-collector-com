package trusts

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// now is fixed so every "days ago" fixture below is a literal, reproducible
// instant, not time.Now() drifting between runs.
var inactiveTestNow = time.Date(2026, 9, 27, 0, 0, 0, 0, time.UTC)

func daysAgo(n int) time.Time { return inactiveTestNow.AddDate(0, 0, -n) }

// TestInactiveDetector_BidirectionalBothStale_Triggers (I1): both directions
// past the 180-day threshold must trigger, and the entity must marshal under
// "name" - marshalTrust (pkg/types/finding.go) reads only AffectedEntity.Name,
// never DisplayName, so a detector that fills DisplayName produces an entity
// with no name at all in the emitted JSON. Verified by mutation (filling
// DisplayName instead of Name) during development: this test alone caught
// it, going red before the fix was reverted.
func TestInactiveDetector_BidirectionalBothStale_Triggers(t *testing.T) {
	data := &audit.DetectorData{
		IncludeDetails: true,
		Now:            inactiveTestNow,
		Trusts: []types.Trust{
			{
				TargetDomain:           "gone.example.com",
				TrustDirection:         "Bidirectional",
				OutgoingPasswordDate:   daysAgo(200),
				OutgoingPasswordSource: "replmetadata",
				IncomingPasswordDate:   daysAgo(200),
				IncomingPasswordSource: "replmetadata",
			},
		},
	}

	findings := NewInactiveDetector().Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 1 {
		t.Fatalf("expected exactly 1 finding with Count 1, got %+v", findings)
	}
	if len(findings[0].AffectedEntities) != 1 {
		t.Fatalf("AffectedEntities = %+v, want exactly 1 entry", findings[0].AffectedEntities)
	}
	raw, err := json.Marshal(findings[0].AffectedEntities[0])
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	if !strings.Contains(string(raw), `"name":"gone.example.com"`) {
		t.Fatalf("marshaled entity = %s, want to contain \"name\":\"gone.example.com\"", raw)
	}
}

// TestInactiveDetector_OneDirectionStaleOneFresh_NoFinding (I2): TRUST_INACTIVE
// requires ALL available directions to be stale - one fresh direction means
// the trust is still rotating on at least one side, which is exactly the
// case ANSSI_R42 exists to catch, not TRUST_INACTIVE. Verified by mutation
// (flipping the aggregation from AND to OR) during development: this test
// alone caught it, going red before the fix was reverted.
func TestInactiveDetector_OneDirectionStaleOneFresh_NoFinding(t *testing.T) {
	data := &audit.DetectorData{
		Now: inactiveTestNow,
		Trusts: []types.Trust{
			{
				TargetDomain:           "half-alive.example.com",
				TrustDirection:         "Bidirectional",
				OutgoingPasswordDate:   daysAgo(200),
				OutgoingPasswordSource: "replmetadata",
				IncomingPasswordDate:   daysAgo(10),
				IncomingPasswordSource: "replmetadata",
			},
		},
	}
	findings := NewInactiveDetector().Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 0 {
		t.Fatalf("expected Count 0 (one fresh direction blocks TRUST_INACTIVE), got %+v", findings)
	}
}

// TestInactiveDetector_SingleOutgoingDirectionStale_Triggers (I3): a
// one-way trust with its only direction stale must still trigger - "all
// available directions" must not silently require both.
func TestInactiveDetector_SingleOutgoingDirectionStale_Triggers(t *testing.T) {
	data := &audit.DetectorData{
		Now: inactiveTestNow,
		Trusts: []types.Trust{
			{
				TargetDomain:           "oneway.example.com",
				TrustDirection:         "Outbound",
				OutgoingPasswordDate:   daysAgo(200),
				OutgoingPasswordSource: "replmetadata",
			},
		},
	}
	findings := NewInactiveDetector().Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 1 {
		t.Fatalf("expected Count 1 (only available direction is stale), got %+v", findings)
	}
}

// TestInactiveDetector_MIT_Excluded (I4): a MIT realm (trustType 3) has no
// automatic rotation to go stale - flagging it as "inactive" penalizes the
// one trust type that was never expected to rotate. Verified by mutation
// (removing the MIT skip) during development: this test alone caught it,
// going red before the fix was reverted.
func TestInactiveDetector_MIT_Excluded(t *testing.T) {
	data := &audit.DetectorData{
		Now: inactiveTestNow,
		Trusts: []types.Trust{
			{
				TargetDomain:           "realm.example.com",
				TrustDirection:         "Bidirectional",
				TrustProtocolType:      "MIT",
				OutgoingPasswordDate:   daysAgo(400),
				OutgoingPasswordSource: "replmetadata",
				IncomingPasswordDate:   daysAgo(400),
				IncomingPasswordSource: "replmetadata",
			},
		},
	}
	findings := NewInactiveDetector().Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 0 {
		t.Fatalf("expected Count 0 (MIT excluded), got %+v", findings)
	}
}

// TestInactiveDetector_WhenCreatedOldEverythingElseFresh_NoFinding (I5):
// WhenCreated must never feed the age computation - a trust created years
// ago whose secret rotation is working fine (fresh replmetadata) must not
// trigger just because of its age.
func TestInactiveDetector_WhenCreatedOldEverythingElseFresh_NoFinding(t *testing.T) {
	data := &audit.DetectorData{
		Now: inactiveTestNow,
		Trusts: []types.Trust{
			{
				TargetDomain:           "long-lived.example.com",
				TrustDirection:         "Bidirectional",
				WhenCreated:            "20210101000000.0Z",
				WhenChanged:            daysAgo(5),
				OutgoingPasswordDate:   daysAgo(5),
				OutgoingPasswordSource: "replmetadata",
				IncomingPasswordDate:   daysAgo(5),
				IncomingPasswordSource: "replmetadata",
			},
		},
	}
	findings := NewInactiveDetector().Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 0 {
		t.Fatalf("expected Count 0 (WhenCreated must not be read as an age), got %+v", findings)
	}
}

// TestInactiveDetector_Boundary179_NoFinding_180_Triggers (I6) fixes the
// exact `>=` boundary at the 180-day threshold.
func TestInactiveDetector_Boundary179_NoFinding_180_Triggers(t *testing.T) {
	base := func(age int) *audit.DetectorData {
		return &audit.DetectorData{
			Now: inactiveTestNow,
			Trusts: []types.Trust{
				{
					TargetDomain:           "boundary.example.com",
					TrustDirection:         "Outbound",
					OutgoingPasswordDate:   daysAgo(age),
					OutgoingPasswordSource: "replmetadata",
				},
			},
		}
	}
	if f := NewInactiveDetector().Detect(context.Background(), base(179)); f[0].Count != 0 {
		t.Fatalf("179 days: Count = %d, want 0", f[0].Count)
	}
	if f := NewInactiveDetector().Detect(context.Background(), base(180)); f[0].Count != 1 {
		t.Fatalf("180 days: Count = %d, want 1", f[0].Count)
	}
}

// TestInactiveDetector_DisabledDirection_NoFinding covers trustDirection 0
// (disabled trust, GetTrusts leaves TrustDirection empty): no direction
// rotates, so none can be "stale" either - must not be treated as
// vacuously "all directions stale".
func TestInactiveDetector_DisabledDirection_NoFinding(t *testing.T) {
	data := &audit.DetectorData{
		Now: inactiveTestNow,
		Trusts: []types.Trust{
			{TargetDomain: "disabled.example.com", TrustDirection: "", WhenChanged: daysAgo(400)},
		},
	}
	findings := NewInactiveDetector().Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 0 {
		t.Fatalf("expected Count 0 (disabled trust has no direction to evaluate), got %+v", findings)
	}
}

// TestInactiveDetector_NoExactDate_WhenChangedBoundOld_Triggers exercises the
// whenChanged-as-bound fallback when neither replmetadata nor the trust
// account produced an exact date: a bound old enough to clear the threshold
// is enough to declare the secret at least that old.
func TestInactiveDetector_NoExactDate_WhenChangedBoundOld_Triggers(t *testing.T) {
	data := &audit.DetectorData{
		Now: inactiveTestNow,
		Trusts: []types.Trust{
			{TargetDomain: "bound-only.example.com", TrustDirection: "Outbound", WhenChanged: daysAgo(400)},
		},
	}
	findings := NewInactiveDetector().Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 1 {
		t.Fatalf("expected Count 1 (whenChanged bound past threshold), got %+v", findings)
	}
}

// TestInactiveDetector_NoExactDate_WhenChangedBoundRecent_NoFinding: the bound
// is young, so there is no basis to call the secret stale - the detector
// must stay silent (never claim "recent" affirmatively, just not fire).
func TestInactiveDetector_NoExactDate_WhenChangedBoundRecent_NoFinding(t *testing.T) {
	data := &audit.DetectorData{
		Now: inactiveTestNow,
		Trusts: []types.Trust{
			{TargetDomain: "bound-only-fresh.example.com", TrustDirection: "Outbound", WhenChanged: daysAgo(10)},
		},
	}
	findings := NewInactiveDetector().Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 0 {
		t.Fatalf("expected Count 0 (bound too young to declare stale), got %+v", findings)
	}
}

// TestInactiveDetector_NoDataAtAll_Silence: neither an exact date nor
// WhenChanged is available - the detector must stay silent, never guess.
func TestInactiveDetector_NoDataAtAll_Silence(t *testing.T) {
	data := &audit.DetectorData{
		Now: inactiveTestNow,
		Trusts: []types.Trust{
			{TargetDomain: "no-data.example.com", TrustDirection: "Outbound"},
		},
	}
	findings := NewInactiveDetector().Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 0 {
		t.Fatalf("expected Count 0 (no date at all), got %+v", findings)
	}
}

// TestInactiveDetector_MetadataOldButWhenChangedRecent_StillTriggers is a
// lab-measured trap: whenChanged can be NEWER than the real secret age (an
// unrelated msDS-TrustForestTrustInfo rewrite moved a live lab TDO's
// whenChanged several minutes past its trustAuth* metadata). A resolver
// that checked whenChanged before the exact reading would understate the
// age and miss a genuinely stale secret. Verified by mutation (in
// trustDirectionAge, checking whenChanged before exactSource) during
// development: this test alone caught it, going red before the fix was
// reverted.
func TestInactiveDetector_MetadataOldButWhenChangedRecent_StillTriggers(t *testing.T) {
	data := &audit.DetectorData{
		Now: inactiveTestNow,
		Trusts: []types.Trust{
			{
				TargetDomain:           "stale-but-touched.example.com",
				TrustDirection:         "Outbound",
				OutgoingPasswordDate:   daysAgo(200),
				OutgoingPasswordSource: "replmetadata",
				WhenChanged:            daysAgo(5), // recent, unrelated TDO write
			},
		},
	}
	findings := NewInactiveDetector().Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 1 {
		t.Fatalf("expected Count 1 (exact metadata age must win over a recent whenChanged), got %+v", findings)
	}
}

// TestInactiveDetector_IncomingUnresolvedBlocksBidirectional (T-MV3): a
// bidirectional trust whose outgoing direction is definitively stale
// (replmetadata, J-200) must still NOT trigger when the incoming direction
// has no data at all (no source, no WhenChanged bound) - "all available
// directions stale" requires actually resolving every direction the trust
// has, not just the ones that happen to carry a date. Silence on the
// unresolved incoming direction, not a guess that it must also be stale.
// Verified by mutation (in Detect, changing the incoming branch's `if !ok {
// allStale = false }` to skip the direction instead, leaving allStale
// untouched) during development: this test alone caught it, going red before
// the fix was reverted.
func TestInactiveDetector_IncomingUnresolvedBlocksBidirectional(t *testing.T) {
	data := &audit.DetectorData{
		Now: inactiveTestNow,
		Trusts: []types.Trust{
			{
				TargetDomain:           "incoming-unresolved.example.com",
				TrustDirection:         "Bidirectional",
				OutgoingPasswordDate:   daysAgo(200),
				OutgoingPasswordSource: "replmetadata",
				// IncomingPasswordSource left empty, WhenChanged left zero:
				// the incoming direction cannot be resolved at all.
			},
		},
	}
	findings := NewInactiveDetector().Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 0 {
		t.Fatalf("expected Count 0 (incoming direction unresolved must block the bidirectional verdict), got %+v", findings)
	}
}

// TestInactiveDetector_NoStaleTrustsIsLegitimateZero pins Count=0 as a real
// "nothing to report" outcome once the detector can actually evaluate
// trusts, distinguishing it from the previous always-zero dead code (the
// bug this detector was originally written to fix).
func TestInactiveDetector_NoStaleTrustsIsLegitimateZero(t *testing.T) {
	data := &audit.DetectorData{
		Now: inactiveTestNow,
		Trusts: []types.Trust{
			{
				TargetDomain:           "fresh.example.com",
				TrustDirection:         "Bidirectional",
				OutgoingPasswordDate:   daysAgo(5),
				OutgoingPasswordSource: "replmetadata",
				IncomingPasswordDate:   daysAgo(5),
				IncomingPasswordSource: "replmetadata",
			},
		},
	}

	findings := NewInactiveDetector().Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 0 {
		t.Fatalf("expected a single finding with Count=0, got %+v", findings)
	}
}
