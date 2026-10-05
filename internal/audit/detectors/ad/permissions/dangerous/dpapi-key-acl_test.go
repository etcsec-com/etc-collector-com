package dangerous

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// Cause confirmée : engine.go/le detecteur filtraient sur
// "CN=Master Root Keys,CN=System,<baseDN>", un DN qui n'existe dans aucun
// AD (BCKUPKEY_* vivent directement sous CN=System, GUID-suffixed). Le
// détecteur restait donc muet (Count=0) dans tout domaine réel. Ce test
// prouve la réparation : les ACEs réelles arrivent désormais via
// DomainInfo.DPAPIBackupKeyACLs (rempli par le provider ldap sur les vrais
// objets BCKUPKEY_*).
const dpapiDomainDN = "DC=example,DC=com"

func dpapiData(aces ...types.ACLEntry) *audit.DetectorData {
	return &audit.DetectorData{
		IncludeDetails: true,
		DomainInfo: &types.DomainInfo{
			DomainDN:           dpapiDomainDN,
			DomainSID:          "S-1-5-21-1111111111-2222222222-3333333333",
			DPAPIBackupKeyACLs: aces,
		},
	}
}

// TestDPAPIKeyACL_NonPrivilegedAccessFires is RED on today's code: the
// detector filters data.ACLEntries (empty here - the real fix path) by a
// dead DN, so it never sees these ACEs no matter where they are attached.
// After the patch it reads DomainInfo.DPAPIBackupKeyACLs directly and must
// fire.
func TestDPAPIKeyACL_NonPrivilegedAccessFires(t *testing.T) {
	ace := types.ACLEntry{
		ObjectDN:   "CN=BCKUPKEY_PREFERRED,CN=System," + dpapiDomainDN,
		Trustee:    "S-1-5-21-1111111111-2222222222-3333333333-1105", // ordinary user, not privileged
		AceType:    "ACCESS_ALLOWED_ACE_TYPE",
		AccessMask: types.MaskGenericAll,
	}
	data := dpapiData(ace)

	d := NewDPAPIKeyACLDetector()
	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for non-default DPAPI backup key access, got %d", len(findings))
	}
	if findings[0].Count != 1 {
		t.Fatalf("expected Count=1, got %d", findings[0].Count)
	}
}

// TestDPAPIKeyACL_NoFindingWhenNoACLData covers the doctrine "un détecteur
// qui devine est pire qu'un contrôle absent": with no DomainInfo (provider
// didn't run / LDAP denied), the detector must emit nothing, not guess.
func TestDPAPIKeyACL_NoFindingWhenNoACLData(t *testing.T) {
	d := NewDPAPIKeyACLDetector()
	findings := d.Detect(context.Background(), &audit.DetectorData{})
	if len(findings) != 0 {
		t.Fatalf("expected no finding with nil DomainInfo, got %d", len(findings))
	}
}
