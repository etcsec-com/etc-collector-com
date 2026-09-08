package advanced

import (
	"context"
	"testing"
	"time"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// TestLockedAccountAdmin_UACBitIsDeadOnModernDomains freezes the KB305144
// semantics: since Windows Server 2003, the UAC LOCKOUT bit
// (0x10) no longer reflects live lockout state, so the detector must key
// off lockoutTime instead. Before the fix, isLocked was
// `u.LockedOut || (u.UserAccountControl&0x10) != 0`, but LockedOut is
// itself derived from that same dead bit (parser.go), so the whole
// expression could never fire independently of it.
func TestLockedAccountAdmin_UACBitIsDeadOnModernDomains(t *testing.T) {
	d := NewLockedAccountAdminDetector()

	baseUser := types.User{
		MemberOf: []string{"CN=Domain Admins,CN=Users,DC=corp,DC=local"},
	}

	cases := []struct {
		name      string
		user      types.User
		wantCount int
	}{
		{
			name: "UAC LOCKOUT bit set, no lockoutTime (modern domain false signal)",
			user: func() types.User {
				u := baseUser
				u.UserAccountControl = 0x10
				u.LockedOut = true // as set by parser.go from the same dead bit
				return u
			}(),
			wantCount: 0,
		},
		{
			name: "lockoutTime set, UAC bit clear (real lockout)",
			user: func() types.User {
				u := baseUser
				u.LockoutTime = time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
				return u
			}(),
			wantCount: 1,
		},
		{
			name:      "no lockout signal at all",
			user:      baseUser,
			wantCount: 0,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data := &audit.DetectorData{Users: []types.User{tc.user}}
			findings := d.Detect(context.Background(), data)
			if len(findings) != 1 {
				t.Fatalf("expected exactly 1 finding, got %d", len(findings))
			}
			if findings[0].Count != tc.wantCount {
				t.Fatalf("expected count=%d, got %d (UAC-bit dead-code regression?)",
					tc.wantCount, findings[0].Count)
			}
		})
	}
}
