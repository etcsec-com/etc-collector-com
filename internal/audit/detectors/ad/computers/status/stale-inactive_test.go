package status

import (
	"context"
	"testing"
	"time"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

func TestStaleInactive_PrefersReplicatedTimestamp(t *testing.T) {
	now := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	staleTime := now.AddDate(0, 0, -120)
	recentTime := now.AddDate(0, 0, -5)

	t.Run("stale LastLogonTimestamp fires even with a recent per-DC LastLogon", func(t *testing.T) {
		// LastLogon is per-DC and never replicated: a recent value on the
		// queried DC does not mean the computer is actually active domain-wide.
		// LastLogonTimestamp (replicated) must take priority.
		data := &audit.DetectorData{
			Now: now,
			Computers: []types.Computer{
				{DN: "CN=WS-05,OU=Workstations,DC=example,DC=com", LastLogonTimestamp: staleTime, LastLogon: recentTime},
			},
		}
		findings := NewStaleInactiveDetector().Detect(context.Background(), data)
		if len(findings) != 1 {
			t.Fatalf("expected exactly 1 finding, got %d", len(findings))
		}
		if findings[0].Count != 1 {
			t.Fatalf("stale replicated timestamp must fire even with a fresh per-DC value, got count=%d", findings[0].Count)
		}
	})

	t.Run("recent LastLogonTimestamp does not fire", func(t *testing.T) {
		data := &audit.DetectorData{
			Now: now,
			Computers: []types.Computer{
				{DN: "CN=WS-06,OU=Workstations,DC=example,DC=com", LastLogonTimestamp: recentTime, LastLogon: staleTime},
			},
		}
		findings := NewStaleInactiveDetector().Detect(context.Background(), data)
		if len(findings) != 1 {
			t.Fatalf("expected exactly 1 finding, got %d", len(findings))
		}
		if findings[0].Count != 0 {
			t.Fatalf("a recent replicated timestamp means the computer is active, got count=%d", findings[0].Count)
		}
	})

	t.Run("falls back to LastLogon when LastLogonTimestamp was never populated", func(t *testing.T) {
		data := &audit.DetectorData{
			Now: now,
			Computers: []types.Computer{
				{DN: "CN=WS-07,OU=Workstations,DC=example,DC=com", LastLogon: staleTime},
			},
		}
		findings := NewStaleInactiveDetector().Detect(context.Background(), data)
		if len(findings) != 1 {
			t.Fatalf("expected exactly 1 finding, got %d", len(findings))
		}
		if findings[0].Count != 1 {
			t.Fatalf("stale LastLogon fallback must still fire, got count=%d", findings[0].Count)
		}
	})
}
