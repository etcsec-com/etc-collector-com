package security

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// This detector reads no BitLocker signal at all (its own TODO said
// so); it is "enabled server" as a manual-review proxy. The prior Title
// ("BitLocker Not Detected") and High severity claimed a confirmed
// vulnerability that was never actually checked.
func TestNoBitlocker_DoesNotClaimAConfirmedDetection(t *testing.T) {
	c := types.Computer{DN: "CN=SRV01,DC=example,DC=com", OperatingSystem: "Windows Server 2022"}
	data := &audit.DetectorData{Computers: []types.Computer{c}}

	findings := NewNoBitlockerDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.Count != 1 {
		t.Fatalf("Count = %d, want 1 (the underlying server-inventory logic is unchanged)", f.Count)
	}
	if f.Severity == types.SeverityHigh {
		t.Fatalf("Severity = %q, want it downgraded from High: no BitLocker absence was actually confirmed", f.Severity)
	}
	if f.Title == "BitLocker Not Detected" {
		t.Fatalf("Title still claims a detection (%q) that this code does not perform", f.Title)
	}
}
