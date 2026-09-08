package nesting

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// TestDangerousGroupNesting_FiresOnRealPipelineData covers a bug where the
// detector read group.DistinguishedName, an "alias for DN" field that
// parseGroup (internal/providers/ldap/parser.go) never assigns - only DN is
// populated. On real pipeline data DistinguishedName is always "", so
// isProtected was always false and the detector could never fire, no
// matter how a real domain nested Domain Admins.
func TestDangerousGroupNesting_FiresOnRealPipelineData(t *testing.T) {
	data := &audit.DetectorData{
		Groups: []types.Group{
			{
				// Only DN set, matching what parseGroup actually produces -
				// DistinguishedName is deliberately left empty.
				DN:       "CN=Domain Admins,CN=Users,DC=contoso,DC=com",
				MemberOf: []string{"CN=HelpDesk,OU=Groups,DC=contoso,DC=com"}, // non-protected parent
			},
		},
	}

	findings := NewDangerousNestingDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 1 {
		t.Fatalf("expected Count=1 (Domain Admins nested in a non-protected group), got %d", findings[0].Count)
	}
}
