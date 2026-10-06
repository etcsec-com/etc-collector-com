package anssi

import (
	"context"
	"testing"
	"time"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// TestR28KrbtgtRotation_270DaysIsCompliant: ANSSI PA-099 R41
// (p.53) requires rotating krbtgt "chaque année" (once a year), not every 180
// days. A krbtgt password changed 270 days ago is within ANSSI's own
// tolerance and must not be flagged Critical. This test would have FAILED
// against the old 180-day threshold (270 > 180 → flagged) and passes now
// that the threshold matches the source (270 < 365 → compliant).
func TestR28KrbtgtRotation_270DaysIsCompliant(t *testing.T) {
	now := time.Date(2026, 9, 8, 0, 0, 0, 0, time.UTC)
	data := &audit.DetectorData{
		Now: now,
		Users: []types.User{
			{ObjectSID: "S-1-5-21-1-2-3-502", SAMAccountName: "krbtgt", PasswordLastSet: now.AddDate(0, 0, -270)},
		},
	}
	findings := NewR28KrbtgtRotationDetector().Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 0 {
		t.Fatalf("expected krbtgt rotated 270 days ago to be compliant with the 1-year ANSSI R41 threshold, got %+v", findings)
	}
}

// TestR28KrbtgtRotation_400DaysIsFlagged confirms the detector still fires
// once the real ANSSI threshold (1 year) is exceeded.
func TestR28KrbtgtRotation_400DaysIsFlagged(t *testing.T) {
	now := time.Date(2026, 9, 8, 0, 0, 0, 0, time.UTC)
	data := &audit.DetectorData{
		Now: now,
		Users: []types.User{
			{ObjectSID: "S-1-5-21-1-2-3-502", SAMAccountName: "krbtgt", PasswordLastSet: now.AddDate(0, 0, -400)},
		},
	}
	findings := NewR28KrbtgtRotationDetector().Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 1 {
		t.Fatalf("expected krbtgt rotated 400 days ago to be flagged, got %+v", findings)
	}
}
