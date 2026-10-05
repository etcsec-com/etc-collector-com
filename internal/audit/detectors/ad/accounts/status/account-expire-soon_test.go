package status

import (
	"context"
	"testing"
	"time"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// No official source (MS-ADA1, Microsoft Learn AD hardening guidance, ANSSI,
// CIS) prescribes a specific "expiring soon" lookahead window for
// accountExpires - see the comment above thirtyDaysFromNow in
// account-expire-soon.go. The 30-day window is a product benchmark, not a
// compliance requirement. These tests pin the documented boundary so a
// future change to the window (or to one of the exclusions it depends on)
// is a deliberate, reviewed decision rather than an accidental regression.
func TestAccountExpireSoon_WindowBoundary(t *testing.T) {
	now := time.Date(2026, 9, 8, 0, 0, 0, 0, time.UTC)

	cases := []struct {
		name      string
		user      types.User
		wantCount int
	}{
		{
			name:      "expires in 29 days - inside the 30-day window",
			user:      types.User{AccountExpires: now.AddDate(0, 0, 29)},
			wantCount: 1,
		},
		{
			name:      "expires in exactly 30 days - boundary excluded (strict Before)",
			user:      types.User{AccountExpires: now.AddDate(0, 0, 30)},
			wantCount: 0,
		},
		{
			name:      "expires in 31 days - outside the window",
			user:      types.User{AccountExpires: now.AddDate(0, 0, 31)},
			wantCount: 0,
		},
		{
			name:      "already expired - not this detector's job (an already-expired account is not 'expiring soon')",
			user:      types.User{AccountExpires: now.AddDate(0, 0, -1)},
			wantCount: 0,
		},
		{
			name:      "never expires (zero accountExpires) - not flagged",
			user:      types.User{AccountExpires: time.Time{}},
			wantCount: 0,
		},
		{
			name:      "disabled account expiring in 10 days - not flagged",
			user:      types.User{Disabled: true, AccountExpires: now.AddDate(0, 0, 10)},
			wantCount: 0,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data := &audit.DetectorData{Now: now, Users: []types.User{tc.user}}
			f := NewAccountExpireSoonDetector().Detect(context.Background(), data)[0]
			if f.Count != tc.wantCount {
				t.Fatalf("expected Count=%d, got %d", tc.wantCount, f.Count)
			}
		})
	}
}
