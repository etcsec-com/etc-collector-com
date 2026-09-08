package helpers

import (
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

func TestTier0Members_DirectMembership(t *testing.T) {
	data := &audit.DetectorData{
		Groups: []types.Group{
			{SAMAccountName: "Domain Admins", DN: "CN=Domain Admins,DC=test,DC=local",
				Members: []string{"CN=alice,DC=test,DC=local", "CN=bob,DC=test,DC=local"}},
		},
	}
	got := Tier0Members(data, nil)
	if !got["cn=alice,dc=test,dc=local"] || !got["cn=bob,dc=test,dc=local"] {
		t.Fatalf("expected alice + bob in Tier 0, got %v", got)
	}
}

func TestTier0Members_RecursiveNesting(t *testing.T) {
	// Domain Admins ⊃ NestedAdmins ⊃ deepUser
	data := &audit.DetectorData{
		Groups: []types.Group{
			{SAMAccountName: "Domain Admins", DN: "CN=DA,DC=test,DC=local",
				Members: []string{"CN=NestedAdmins,DC=test,DC=local"}},
			{SAMAccountName: "NestedAdmins", DN: "CN=NestedAdmins,DC=test,DC=local",
				Members: []string{"CN=deepUser,DC=test,DC=local"}},
		},
	}
	got := Tier0Members(data, nil)
	if !got["cn=deepuser,dc=test,dc=local"] {
		t.Fatalf("recursive expansion missed deepUser, got %v", got)
	}
}

func TestTier0Members_AdminCountOne(t *testing.T) {
	// User has AdminCount=1 (AdminSDHolder protected) but isn't currently
	// in any admin group → should still be flagged Tier 0.
	data := &audit.DetectorData{
		Users: []types.User{
			{DN: "CN=ghost,DC=test,DC=local", SAMAccountName: "ghost", AdminCount: true},
		},
	}
	got := Tier0Members(data, nil)
	if !got["cn=ghost,dc=test,dc=local"] {
		t.Fatalf("AdminCount=1 user should be Tier 0, got %v", got)
	}
}

func TestTier0Members_CustomGroupDNs(t *testing.T) {
	data := &audit.DetectorData{
		Groups: []types.Group{
			{SAMAccountName: "Acme-T0", DN: "CN=Acme-T0,OU=AcmeAdmins,DC=test,DC=local",
				Members: []string{"CN=charlie,DC=test,DC=local"}},
		},
	}
	custom := []string{"CN=Acme-T0,OU=AcmeAdmins,DC=test,DC=local"}
	got := Tier0Members(data, custom)
	if !got["cn=charlie,dc=test,dc=local"] {
		t.Fatalf("custom Tier 0 group member missed, got %v", got)
	}
}

func TestTier0Members_CycleDoesNotInfinite(t *testing.T) {
	// Domain Admins ⊃ Loop ⊃ Domain Admins (cycle). Must terminate.
	data := &audit.DetectorData{
		Groups: []types.Group{
			{SAMAccountName: "Domain Admins", DN: "CN=DA,DC=test,DC=local",
				Members: []string{"CN=Loop,DC=test,DC=local"}},
			{SAMAccountName: "Loop", DN: "CN=Loop,DC=test,DC=local",
				Members: []string{"CN=DA,DC=test,DC=local", "CN=enduser,DC=test,DC=local"}},
		},
	}
	got := Tier0Members(data, nil)
	if !got["cn=enduser,dc=test,dc=local"] {
		t.Fatalf("cycle case should still expand to enduser, got %v", got)
	}
}

func TestTier0Groups_TransitiveNesting(t *testing.T) {
	data := &audit.DetectorData{
		Groups: []types.Group{
			{SAMAccountName: "Domain Admins", DN: "CN=DA,DC=test,DC=local",
				Members: []string{"CN=Inner,DC=test,DC=local"}},
			{SAMAccountName: "Inner", DN: "CN=Inner,DC=test,DC=local"},
		},
	}
	got := Tier0Groups(data, nil)
	if !got["cn=inner,dc=test,dc=local"] {
		t.Fatalf("Inner group should be Tier 0 by nesting, got %v", got)
	}
}
