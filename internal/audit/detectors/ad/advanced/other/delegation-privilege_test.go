package other

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// TestDelegationPrivilege_ReadsFromGPOPolicies covers a bug where the
// detector used to key off types.User.HasSeEnableDelegationPrivilege, a
// field nothing in the codebase ever assigns, so it was permanently stuck
// at Count==0 regardless of what the domain's GPOs actually grant. This
// pins that the detector instead reads the already-collected GPO
// [Privilege Rights] data (data.GPOPolicies), which is where
// SeEnableDelegationPrivilege SIDs really live (internal/providers/smb/
// gptmpl_parser.go).
func TestDelegationPrivilege_ReadsFromGPOPolicies(t *testing.T) {
	policies := map[string]*audit.GPOPolicy{
		"{GUID-1}": {
			GUID: "{GUID-1}",
			PrivilegeRights: &audit.PrivilegeRights{
				SeEnableDelegationPrivilege: []string{
					"S-1-5-32-544",        // Administrators - safe
					"S-1-5-21-1-2-3-1104", // ordinary user - unsafe
				},
			},
		},
	}

	data := &audit.DetectorData{
		IncludeDetails: true,
		GPOPolicies:    policies,
		// A stale/never-assigned User field must NOT drive detection.
		Users: []types.User{{SAMAccountName: "decoy", HasSeEnableDelegationPrivilege: false}},
	}

	findings := NewDelegationPrivilegeDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}

	f := findings[0]
	if f.Count != 1 {
		t.Fatalf("expected Count=1 (only the non-Administrators SID), got %d", f.Count)
	}
	if len(f.AffectedEntities) != 1 {
		t.Fatalf("expected 1 affected entity, got %d", len(f.AffectedEntities))
	}
	if f.AffectedEntities[0].SID != "S-1-5-21-1-2-3-1104" {
		t.Fatalf("unexpected affected SID: %s", f.AffectedEntities[0].SID)
	}
}
