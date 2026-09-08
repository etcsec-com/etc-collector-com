package password

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// TestCannotChange_UACFlagFlagged is a coverage test, not a red/green
// regression test: no code defect was found in this detector (see the
// Detect doc comment) - the open item was empirical confirmation, not
// correctness. This pins that ADS_UF_PASSWD_CANT_CHANGE (0x0040) is read
// correctly.
func TestCannotChange_UACFlagFlagged(t *testing.T) {
	data := &audit.DetectorData{
		IncludeDetails: true,
		Users: []types.User{
			{SAMAccountName: "shared-kiosk", UserAccountControl: 0x0040},
		},
	}

	findings := NewCannotChangeDetector().Detect(context.Background(), data)
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1", findings[0].Count)
	}
}

// TestCannotChange_FlagNotSetNotFlagged guards the negative case.
func TestCannotChange_FlagNotSetNotFlagged(t *testing.T) {
	data := &audit.DetectorData{
		Users: []types.User{{SAMAccountName: "ordinary", UserAccountControl: 0x0200}}, // NORMAL_ACCOUNT
	}

	findings := NewCannotChangeDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0", findings[0].Count)
	}
}
