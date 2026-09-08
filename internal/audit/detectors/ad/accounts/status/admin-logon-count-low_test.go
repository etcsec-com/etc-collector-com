package status

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// Microsoft Learn, "Logon-Count attribute"
// (learn.microsoft.com/en-us/windows/win32/adschema/a-logoncount) documents
// logonCount as "not replicated and ... maintained on each domain controller
// in the domain", and states "A value of 0 indicates that the value is
// unknown." Before this fix, the detector treated logonCount==0 exactly like
// any other "low" value (< 5) and flagged it as evidence of an unused admin
// account - reading a documented "unknown" as a confirmed negative.
func TestAdminLogonCountLow_ZeroIsInconclusiveNotFlagged(t *testing.T) {
	u := types.User{
		AdminCount: true,
		LogonCount: 0,
	}
	data := &audit.DetectorData{Users: []types.User{u}}

	f := NewAdminLogonCountLowDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("logonCount=0 is documented as unknown, not zero logons; must not be flagged, got Count=%d", f.Count)
	}
}

func TestAdminLogonCountLow_LowNonZeroStillFlagged(t *testing.T) {
	u := types.User{
		AdminCount: true,
		LogonCount: 2,
	}
	data := &audit.DetectorData{Users: []types.User{u}}

	f := NewAdminLogonCountLowDetector().Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("a low but known (non-zero) logonCount is still a lead worth surfacing, got Count=%d", f.Count)
	}
}

func TestAdminLogonCountLow_HighCountNotFlagged(t *testing.T) {
	u := types.User{
		AdminCount: true,
		LogonCount: 500,
	}
	data := &audit.DetectorData{Users: []types.User{u}}

	f := NewAdminLogonCountLowDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("expected Count=0, got %d", f.Count)
	}
}

func TestAdminLogonCountLow_NonAdminNotFlagged(t *testing.T) {
	u := types.User{
		AdminCount: false,
		LogonCount: 0,
	}
	data := &audit.DetectorData{Users: []types.User{u}}

	f := NewAdminLogonCountLowDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("expected Count=0, got %d", f.Count)
	}
}

func TestAdminLogonCountLow_DisabledAdminNotFlagged(t *testing.T) {
	u := types.User{
		AdminCount: true,
		Disabled:   true,
		LogonCount: 1,
	}
	data := &audit.DetectorData{Users: []types.User{u}}

	f := NewAdminLogonCountLowDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("expected Count=0, got %d", f.Count)
	}
}
