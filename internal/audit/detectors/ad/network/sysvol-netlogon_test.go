package network

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
)

// SYSVOL_NETLOGON_PERMISSIONS fired an unconditional
// High-severity Finding without reading any SYSVOL/NETLOGON share-permission
// data (none is collectable today: the SMB provider only reads file
// content/attributes via go-smb2, whose public API exposes no security
// descriptor read, and LDAP ACLEntries carries AD object ACLs, not SMB
// share ACLs). "Un detecteur qui devine est pire qu'un controle absent":
// it must emit nothing until that data is actually collected.

func TestSysvolNetlogon_NeverGuessesWithoutData(t *testing.T) {
	findings := NewSysvolNetlogonDetector().Detect(context.Background(), &audit.DetectorData{IncludeDetails: true})
	if len(findings) != 0 {
		t.Fatalf("SYSVOL_NETLOGON_PERMISSIONS must not emit any finding while share permissions aren't collected, got %d: %+v", len(findings), findings)
	}
}

func TestSysvolNetlogon_NotRegistered(t *testing.T) {
	if _, ok := audit.DefaultRegistry.Get("SYSVOL_NETLOGON_PERMISSIONS"); ok {
		t.Fatalf("SYSVOL_NETLOGON_PERMISSIONS must stay unregistered until it can measure real share permissions")
	}
}
