package high

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// TestGpoToDADetector covers the fact that PATH_GPO_TO_DA used to title
// EVERY weak-ACL GPO "Critical - Path to Domain Admin" regardless of
// whether the GPO was linked to anything at all, or linked only to a
// container with no Domain Controller and no AdminCount-protected account
// underneath. An orphaned GPO with a modifiable ACL and zero links has no
// path to anything; a GPO linked only to an ordinary OU is not established
// as a path to DA either.
func TestGpoToDADetector(t *testing.T) {
	domainSID := "S-1-5-21-1111111111-2222222222-3333333333"
	nonAdminSID := domainSID + "-9999"

	weakACE := func(gpoDN string) audit.GPOAcl {
		return audit.GPOAcl{
			GPODN:      gpoDN,
			Trustee:    nonAdminSID,
			AccessMask: types.MaskWriteProperty,
			AceType:    "ACCESS_ALLOWED",
		}
	}

	baseData := func() *audit.DetectorData {
		return &audit.DetectorData{
			DomainInfo:     &types.DomainInfo{DomainSID: domainSID},
			IncludeDetails: true,
		}
	}

	t.Run("weak ACL, zero GPO links -> not flagged (orphaned GPO has no path)", func(t *testing.T) {
		data := baseData()
		gpoDN := "CN={AAAAAAAA-0000-0000-0000-000000000001},CN=Policies,CN=System,DC=contoso,DC=com"
		data.GPOs = []types.GPO{{DN: gpoDN, CN: "{AAAAAAAA-0000-0000-0000-000000000001}", GUID: "{AAAAAAAA-0000-0000-0000-000000000001}", Name: "Orphaned"}}
		data.GPOAcls = []audit.GPOAcl{weakACE(gpoDN)}
		// No GPOLinks entries at all.

		f := detect(t, data)
		if f.Count != 0 {
			t.Fatalf("orphaned weak-ACL GPO must not be flagged as path to DA, got Count=%d", f.Count)
		}
	})

	t.Run("weak ACL, linked only to a non-privileged OU -> not flagged", func(t *testing.T) {
		data := baseData()
		gpoDN := "CN={BBBBBBBB-0000-0000-0000-000000000002},CN=Policies,CN=System,DC=contoso,DC=com"
		ouDN := "OU=Marketing,DC=contoso,DC=com"
		data.GPOs = []types.GPO{{DN: gpoDN, CN: "{BBBBBBBB-0000-0000-0000-000000000002}", GUID: "{BBBBBBBB-0000-0000-0000-000000000002}", Name: "MarketingGPO"}}
		data.GPOAcls = []audit.GPOAcl{weakACE(gpoDN)}
		data.GPOLinks = []audit.GPOLink{
			{GPOCN: "{BBBBBBBB-0000-0000-0000-000000000002}", LinkedTo: ouDN, LinkEnabled: true},
		}
		// Ordinary user in that OU, not AdminCount.
		data.Users = []types.User{{DN: "CN=Alice,OU=Marketing,DC=contoso,DC=com", SAMAccountName: "alice", AdminCount: false}}

		f := detect(t, data)
		if f.Count != 0 {
			t.Fatalf("weak-ACL GPO linked only to a non-privileged OU must not be flagged, got Count=%d", f.Count)
		}
	})

	t.Run("weak ACL, link disabled -> not flagged", func(t *testing.T) {
		data := baseData()
		gpoDN := "CN={CCCCCCCC-0000-0000-0000-000000000003},CN=Policies,CN=System,DC=contoso,DC=com"
		dcOU := "OU=Domain Controllers,DC=contoso,DC=com"
		data.GPOs = []types.GPO{{DN: gpoDN, CN: "{CCCCCCCC-0000-0000-0000-000000000003}", GUID: "{CCCCCCCC-0000-0000-0000-000000000003}", Name: "DisabledLinkGPO"}}
		data.GPOAcls = []audit.GPOAcl{weakACE(gpoDN)}
		data.GPOLinks = []audit.GPOLink{
			{GPOCN: "{CCCCCCCC-0000-0000-0000-000000000003}", LinkedTo: dcOU, LinkEnabled: false},
		}
		data.DomainControllers = []types.Computer{{DN: "CN=DC01,OU=Domain Controllers,DC=contoso,DC=com", SAMAccountName: "DC01$"}}

		f := detect(t, data)
		if f.Count != 0 {
			t.Fatalf("weak-ACL GPO with only a disabled link must not be flagged, got Count=%d", f.Count)
		}
	})

	t.Run("weak ACL, linked to OU containing a Domain Controller -> flagged Critical", func(t *testing.T) {
		data := baseData()
		gpoDN := "CN={DDDDDDDD-0000-0000-0000-000000000004},CN=Policies,CN=System,DC=contoso,DC=com"
		dcOU := "OU=Domain Controllers,DC=contoso,DC=com"
		data.GPOs = []types.GPO{{DN: gpoDN, CN: "{DDDDDDDD-0000-0000-0000-000000000004}", GUID: "{DDDDDDDD-0000-0000-0000-000000000004}", Name: "DCPolicyGPO", DisplayName: "Default Domain Controllers Policy"}}
		data.GPOAcls = []audit.GPOAcl{weakACE(gpoDN)}
		data.GPOLinks = []audit.GPOLink{
			{GPOCN: "{DDDDDDDD-0000-0000-0000-000000000004}", LinkedTo: dcOU, LinkEnabled: true},
		}
		data.DomainControllers = []types.Computer{{DN: "CN=DC01," + dcOU, SAMAccountName: "DC01$"}}

		f := detect(t, data)
		if f.Count != 1 {
			t.Fatalf("weak-ACL GPO linked to the DC OU must be flagged, got Count=%d", f.Count)
		}
		if len(f.AffectedEntities) != 1 || f.AffectedEntities[0].SAMAccountName != "Default Domain Controllers Policy" {
			t.Fatalf("unexpected AffectedEntities: %+v", f.AffectedEntities)
		}
	})

	t.Run("weak ACL, linked to OU containing an AdminCount user -> flagged Critical", func(t *testing.T) {
		data := baseData()
		gpoDN := "CN={EEEEEEEE-0000-0000-0000-000000000005},CN=Policies,CN=System,DC=contoso,DC=com"
		tier0OU := "OU=Tier0,DC=contoso,DC=com"
		data.GPOs = []types.GPO{{DN: gpoDN, CN: "{EEEEEEEE-0000-0000-0000-000000000005}", GUID: "{EEEEEEEE-0000-0000-0000-000000000005}", Name: "Tier0GPO"}}
		data.GPOAcls = []audit.GPOAcl{weakACE(gpoDN)}
		data.GPOLinks = []audit.GPOLink{
			{GPOCN: "{EEEEEEEE-0000-0000-0000-000000000005}", LinkedTo: tier0OU, LinkEnabled: true},
		}
		data.Users = []types.User{{DN: "CN=DAUser,OU=Tier0,DC=contoso,DC=com", SAMAccountName: "dauser", AdminCount: true}}

		f := detect(t, data)
		if f.Count != 1 {
			t.Fatalf("weak-ACL GPO linked to an OU with an AdminCount user must be flagged, got Count=%d", f.Count)
		}
	})

	t.Run("weak ACL, linked at domain root -> flagged Critical", func(t *testing.T) {
		data := baseData()
		gpoDN := "CN={FFFFFFFF-0000-0000-0000-000000000006},CN=Policies,CN=System,DC=contoso,DC=com"
		data.GPOs = []types.GPO{{DN: gpoDN, CN: "{FFFFFFFF-0000-0000-0000-000000000006}", GUID: "{FFFFFFFF-0000-0000-0000-000000000006}", Name: "DefaultDomainPolicy"}}
		data.GPOAcls = []audit.GPOAcl{weakACE(gpoDN)}
		data.GPOLinks = []audit.GPOLink{
			{GPOCN: "{FFFFFFFF-0000-0000-0000-000000000006}", LinkedTo: "DC=contoso,DC=com", LinkEnabled: true},
		}

		f := detect(t, data)
		if f.Count != 1 {
			t.Fatalf("weak-ACL GPO linked at the domain root must be flagged, got Count=%d", f.Count)
		}
	})

	t.Run("no weak ACL at all -> not flagged even if linked to DC OU", func(t *testing.T) {
		data := baseData()
		gpoDN := "CN={00000000-0000-0000-0000-000000000007},CN=Policies,CN=System,DC=contoso,DC=com"
		dcOU := "OU=Domain Controllers,DC=contoso,DC=com"
		data.GPOs = []types.GPO{{DN: gpoDN, CN: "{00000000-0000-0000-0000-000000000007}", GUID: "{00000000-0000-0000-0000-000000000007}", Name: "SafeGPO"}}
		// No GPOAcls entries - no weak grant.
		data.GPOLinks = []audit.GPOLink{
			{GPOCN: "{00000000-0000-0000-0000-000000000007}", LinkedTo: dcOU, LinkEnabled: true},
		}
		data.DomainControllers = []types.Computer{{DN: "CN=DC01," + dcOU, SAMAccountName: "DC01$"}}

		f := detect(t, data)
		if f.Count != 0 {
			t.Fatalf("GPO without a weak ACL must never be flagged, got Count=%d", f.Count)
		}
	})
}

// TestGpoToDADetector_MutationCoverage is the LITERAL subtest required by
// this detector's acceptance criteria: a dedicated fixture built from
// scratch (not sharing the weakACE/baseData closures above), exercising
// mutation M1 - anyLinkReachesPrivileged forced to always return false.
// With that mutation applied, the `if !anyLinkReachesPrivileged(...) {
// continue }` guard above skips every GPO unconditionally, so Count drops
// from 1 to 0 and this subtest goes red - unlike the pre-existing "linked
// at domain root" subtest above, this one exists specifically to make that
// kill an explicit, named acceptance gate rather than an incidental side
// effect.
func TestGpoToDADetector_MutationCoverage(t *testing.T) {
	t.Run("weak ACL + enabled link to DC root + DomainControllers present -> count=1 (kills M1)", func(t *testing.T) {
		domainSID := "S-1-5-21-4444444444-5555555555-6666666666"
		gpoDN := "CN={99999999-aaaa-bbbb-cccc-dddddddddddd},CN=Policies,CN=System,DC=contoso,DC=com"

		data := &audit.DetectorData{
			DomainInfo:     &types.DomainInfo{DomainSID: domainSID},
			IncludeDetails: true,
			GPOs: []types.GPO{
				{DN: gpoDN, CN: "{99999999-AAAA-BBBB-CCCC-DDDDDDDDDDDD}", GUID: "{99999999-AAAA-BBBB-CCCC-DDDDDDDDDDDD}", Name: "MutationM1GPO"},
			},
			GPOAcls: []audit.GPOAcl{
				{GPODN: gpoDN, Trustee: domainSID + "-9876", AccessMask: types.MaskWriteDACL, AceType: "ACCESS_ALLOWED"},
			},
			GPOLinks: []audit.GPOLink{
				{GPOCN: "{99999999-AAAA-BBBB-CCCC-DDDDDDDDDDDD}", LinkedTo: "DC=contoso,DC=com", LinkEnabled: true},
			},
			DomainControllers: []types.Computer{
				{DN: "CN=MUTDC1,OU=Domain Controllers,DC=contoso,DC=com", SAMAccountName: "MUTDC1$"},
			},
		}

		f := detect(t, data)
		if f.Count != 1 {
			t.Fatalf("expected count=1 (weak ACL + enabled domain-root link + DC present), got %d", f.Count)
		}
	})
}

func detect(t *testing.T, data *audit.DetectorData) types.Finding {
	t.Helper()
	findings := NewGpoToDADetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	return findings[0]
}
