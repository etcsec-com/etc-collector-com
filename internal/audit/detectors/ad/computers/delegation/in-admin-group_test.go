package delegation

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

const inAdminGroupDomainDN = "DC=example,DC=com"

// Three bugs pinned in one test: double counting, substring
// over-match, and coverage limited to 2 of Microsoft's 15 protected groups.
func TestInAdminGroup(t *testing.T) {
	t.Run("membership in two admin groups is counted once, not twice", func(t *testing.T) {
		c := types.Computer{
			DN: "CN=WKS01," + inAdminGroupDomainDN,
			MemberOf: []string{
				"CN=Domain Admins,CN=Users," + inAdminGroupDomainDN,
				"CN=Enterprise Admins,CN=Users," + inAdminGroupDomainDN,
			},
		}
		data := &audit.DetectorData{IncludeDetails: true, Computers: []types.Computer{c}}
		findings := NewInAdminGroupDetector().Detect(context.Background(), data)
		if len(findings) != 1 {
			t.Fatalf("expected exactly 1 finding, got %d", len(findings))
		}
		if findings[0].Count != 1 {
			t.Fatalf("Count = %d, want 1 (one computer, not one per matching group)", findings[0].Count)
		}
		if len(findings[0].AffectedEntities) != 1 {
			t.Fatalf("AffectedEntities = %d, want 1 (no duplicate entries for the same computer)", len(findings[0].AffectedEntities))
		}
	})

	t.Run("a group merely prefixed by the admin group name does not match", func(t *testing.T) {
		c := types.Computer{
			DN:       "CN=WKS02," + inAdminGroupDomainDN,
			MemberOf: []string{"CN=Administrators2,CN=Users," + inAdminGroupDomainDN},
		}
		data := &audit.DetectorData{Computers: []types.Computer{c}}
		findings := NewInAdminGroupDetector().Detect(context.Background(), data)
		if findings[0].Count != 0 {
			t.Fatalf("Count = %d, want 0: \"Administrators2\" is not \"Administrators\"", findings[0].Count)
		}
	})

	t.Run("Schema Admins is now covered (previously only Domain/Enterprise Admins)", func(t *testing.T) {
		c := types.Computer{
			DN:       "CN=WKS03," + inAdminGroupDomainDN,
			MemberOf: []string{"CN=Schema Admins,CN=Users," + inAdminGroupDomainDN},
		}
		data := &audit.DetectorData{Computers: []types.Computer{c}}
		findings := NewInAdminGroupDetector().Detect(context.Background(), data)
		if findings[0].Count != 1 {
			t.Fatalf("Count = %d, want 1: Schema Admins is one of Microsoft's protected groups (Appendix C)", findings[0].Count)
		}
	})

	t.Run("a domain controller's own Domain Controllers group membership is not flagged", func(t *testing.T) {
		c := types.Computer{
			DN:       "CN=DC01,OU=Domain Controllers," + inAdminGroupDomainDN,
			MemberOf: []string{"CN=Domain Controllers,CN=Users," + inAdminGroupDomainDN},
		}
		data := &audit.DetectorData{Computers: []types.Computer{c}}
		findings := NewInAdminGroupDetector().Detect(context.Background(), data)
		if findings[0].Count != 0 {
			t.Fatalf("Count = %d, want 0: DC membership in its own \"Domain Controllers\" group is expected structure, not an anomaly", findings[0].Count)
		}
	})
}
