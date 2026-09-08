package other

import (
	"context"
	"strings"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// TestDangerousLogonScripts_FlagsNetworkPathWithoutClaimingACLCheck proves two
// things about DANGEROUS_LOGON_SCRIPTS:
//
//  1. The path-substring heuristic actually flags a UNC-style scriptPath and
//     leaves a relative (NETLOGON-resolved) scriptPath alone - the detection
//     logic itself works as intended.
//  2. The finding's description no longer claims to detect "weak ACLs". The
//     code has never read any file/share/NTFS ACL (it only inspects the
//     scriptPath string), so a description promising ACL analysis was false.
//     This assertion fails against the pre-fix description ("Logon scripts
//     with weak ACLs can be modified by attackers...") and passes once the
//     description honestly describes a path-only heuristic.
func TestDangerousLogonScripts_FlagsNetworkPathWithoutClaimingACLCheck(t *testing.T) {
	users := []types.User{
		{DN: "CN=alice,OU=Users,DC=example,DC=com", ScriptPath: `\\fileserver01\netlogon\login.bat`},
		{DN: "CN=bob,OU=Users,DC=example,DC=com", ScriptPath: "login.bat"},
		{DN: "CN=carol,OU=Users,DC=example,DC=com", ScriptPath: ""},
	}
	data := &audit.DetectorData{IncludeDetails: true, Users: users}

	findings := NewDangerousLogonScriptsDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	f := findings[0]

	if f.Count != 1 {
		t.Fatalf("expected Count=1 (only alice's UNC-path script), got %d", f.Count)
	}
	if len(f.AffectedEntities) != 1 || f.AffectedEntities[0].DN != users[0].DN {
		t.Fatalf("expected only alice flagged, got %+v", f.AffectedEntities)
	}

	descLower := strings.ToLower(f.Description)
	if strings.Contains(descLower, "weak acl") {
		t.Fatalf("description still claims to detect weak ACLs, but the code never reads any ACL: %q", f.Description)
	}
	if !strings.Contains(descLower, "does not read") && !strings.Contains(descLower, "not read the file") {
		t.Fatalf("description does not honestly disclose that no ACL is read: %q", f.Description)
	}
}
