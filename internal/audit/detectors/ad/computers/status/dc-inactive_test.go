package status

import (
	"context"
	"testing"
	"time"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

func TestDCInactive_FortyFiveDayThreshold(t *testing.T) {
	now := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)

	t.Run("60 days inactive (previously below the 90-day threshold) DOES fire", func(t *testing.T) {
		data := &audit.DetectorData{
			Now: now,
			DomainControllers: []types.Computer{
				{DN: "CN=DC02,OU=Domain Controllers,DC=example,DC=com", LastLogonTimestamp: now.AddDate(0, 0, -60)},
			},
		}
		findings := NewDCInactiveDetector().Detect(context.Background(), data)
		if len(findings) != 1 {
			t.Fatalf("expected exactly 1 finding, got %d", len(findings))
		}
		if findings[0].Count != 1 {
			t.Fatalf("60 days must fire under the 45-day threshold, got count=%d", findings[0].Count)
		}
	})

	t.Run("30 days inactive does NOT fire", func(t *testing.T) {
		data := &audit.DetectorData{
			Now: now,
			DomainControllers: []types.Computer{
				{DN: "CN=DC03,OU=Domain Controllers,DC=example,DC=com", LastLogonTimestamp: now.AddDate(0, 0, -30)},
			},
		}
		findings := NewDCInactiveDetector().Detect(context.Background(), data)
		if len(findings) != 1 {
			t.Fatalf("expected exactly 1 finding, got %d", len(findings))
		}
		if findings[0].Count != 0 {
			t.Fatalf("30 days is within the 45-day threshold, got count=%d", findings[0].Count)
		}
	})
}
