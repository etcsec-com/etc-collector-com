package computer

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// T_024 — COMPUTER_ACL_GENERICALL carried the same defect as the ACL_* family:
// no trustee filter and no AceType test, so AD's own full-control ACEs made it
// report 74 of 74 computers.

const (
	cgComputerDN = "CN=WS-01,OU=Workstations,DC=example,DC=com"
	cgDomain     = "S-1-5-21-1234567890-1111111111-2222222222"

	cgFullControl = 0x000F01FF
)

func cgData(aces ...types.ACLEntry) *audit.DetectorData {
	return &audit.DetectorData{
		IncludeDetails: true,
		ACLEntries:     aces,
		Computers:      []types.Computer{{DN: cgComputerDN, SAMAccountName: "WS-01$"}},
		ObjectByDN: map[string]*audit.ObjectMeta{
			cgComputerDN: {DN: cgComputerDN, Name: "WS-01", EntityType: types.EntityTypeComputer},
		},
	}
}

func cgDetect(t *testing.T, data *audit.DetectorData) types.Finding {
	t.Helper()
	findings := NewGenericAllDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	return findings[0]
}

func TestComputerGenericAll_SkipsBuiltinAdminTrustees(t *testing.T) {
	t.Run("AD's own full-control ACEs do NOT fire", func(t *testing.T) {
		f := cgDetect(t, cgData(
			types.ACLEntry{ObjectDN: cgComputerDN, Trustee: "S-1-5-18", AccessMask: cgFullControl, AceType: "ACCESS_ALLOWED"},
			types.ACLEntry{ObjectDN: cgComputerDN, Trustee: cgDomain + "-512", AccessMask: cgFullControl, AceType: "ACCESS_ALLOWED"},
			types.ACLEntry{ObjectDN: cgComputerDN, Trustee: "S-1-5-32-544", AccessMask: cgFullControl, AceType: "ACCESS_ALLOWED"},
		))
		if f.Count != 0 {
			t.Fatalf("baseline ACEs on a computer are not a takeover risk, got count=%d", f.Count)
		}
	})

	t.Run("ordinary domain principal with full control DOES fire", func(t *testing.T) {
		// The real RBCD / credential-theft exposure.
		f := cgDetect(t, cgData(
			types.ACLEntry{ObjectDN: cgComputerDN, Trustee: cgDomain + "-93801", AccessMask: cgFullControl, AceType: "ACCESS_ALLOWED"},
		))
		if f.Count != 1 {
			t.Fatalf("a domain principal owning a computer must fire, got count=%d", f.Count)
		}
		if len(f.AffectedEntities) != 1 {
			t.Fatalf("finding must be actionable, got %d entities", len(f.AffectedEntities))
		}
	})

	t.Run("DENY full control does NOT fire", func(t *testing.T) {
		f := cgDetect(t, cgData(
			types.ACLEntry{ObjectDN: cgComputerDN, Trustee: cgDomain + "-93801", AccessMask: cgFullControl, AceType: "ACCESS_DENIED"},
		))
		if f.Count != 0 {
			t.Fatalf("a DENY ace grants nothing, got count=%d", f.Count)
		}
	})
}
