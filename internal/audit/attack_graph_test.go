package audit

import (
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/etcsec-com/etc-collector/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAttackGraph_EmptyGraph(t *testing.T) {
	svc := NewAttackGraphService(nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)
	export := svc.Export(500)

	assert.Equal(t, "1.0", export.Version)
	assert.Equal(t, 0, export.Stats.TotalPaths)
	assert.Empty(t, export.Paths)
	// Well-known nodes (BUILTIN\Administrators etc.) are always added as targets
	assert.NotEmpty(t, export.Targets)
	assert.Empty(t, export.UniqueNodes)
}

func TestAttackGraph_SimpleGroupMembership(t *testing.T) {
	// User -> Domain Admins via group membership
	users := []types.User{
		{
			DN:             "CN=john,CN=Users,DC=test,DC=com",
			SAMAccountName: "john",
			ObjectSID:      "S-1-5-21-1234-5678-9012-1001",
			MemberOf:       []string{"CN=Domain Admins,CN=Users,DC=test,DC=com"},
		},
	}
	groups := []types.Group{
		{
			DN:             "CN=Domain Admins,CN=Users,DC=test,DC=com",
			SAMAccountName: "Domain Admins",
			ObjectSID:      "S-1-5-21-1234-5678-9012-512",
		},
	}
	domain := &types.DomainInfo{
		DomainName: "test.com",
		DomainSID:  "S-1-5-21-1234-5678-9012",
	}

	svc := NewAttackGraphService(users, groups, nil, nil, nil, domain, nil, nil, nil, nil, nil)
	export := svc.Export(500)

	require.NotEmpty(t, export.Targets, "should identify Domain Admins as target")
	require.NotEmpty(t, export.Paths, "should find path from john to Domain Admins")

	path := export.Paths[0]
	assert.Equal(t, types.PathGroupMembership, path.Type)
	assert.Equal(t, 1, path.Hops)
	assert.Contains(t, path.Description, "john")
	assert.Contains(t, path.Description, "Domain Admins")
}

func TestAttackGraph_Kerberoasting(t *testing.T) {
	// User with SPN -> Domain Admins (kerberoasting path)
	users := []types.User{
		{
			DN:                    "CN=svc-sql,CN=Users,DC=test,DC=com",
			SAMAccountName:        "svc-sql",
			ObjectSID:             "S-1-5-21-1234-5678-9012-1100",
			ServicePrincipalNames: []string{"MSSQLSvc/sql01.test.com:1433"},
			MemberOf:              []string{"CN=Domain Admins,CN=Users,DC=test,DC=com"},
		},
	}
	groups := []types.Group{
		{
			DN:             "CN=Domain Admins,CN=Users,DC=test,DC=com",
			SAMAccountName: "Domain Admins",
			ObjectSID:      "S-1-5-21-1234-5678-9012-512",
		},
	}
	domain := &types.DomainInfo{
		DomainName: "test.com",
		DomainSID:  "S-1-5-21-1234-5678-9012",
	}

	svc := NewAttackGraphService(users, groups, nil, nil, nil, domain, nil, nil, nil, nil, nil)
	export := svc.Export(500)

	require.NotEmpty(t, export.Paths)
	path := export.Paths[0]
	assert.Equal(t, types.PathKerberoasting, path.Type)
	assert.Contains(t, path.Description, "Kerberoasted")
	assert.Contains(t, path.Mitigation, "SPN")
}

func TestAttackGraph_ACLAbuse(t *testing.T) {
	// User with GenericAll on Domain Admins group
	users := []types.User{
		{
			DN:             "CN=attacker,CN=Users,DC=test,DC=com",
			SAMAccountName: "attacker",
			ObjectSID:      "S-1-5-21-1234-5678-9012-1200",
		},
	}
	groups := []types.Group{
		{
			DN:             "CN=Domain Admins,CN=Users,DC=test,DC=com",
			SAMAccountName: "Domain Admins",
			ObjectSID:      "S-1-5-21-1234-5678-9012-512",
		},
	}
	acls := []types.ACLEntry{
		{
			ObjectDN:   "CN=Domain Admins,CN=Users,DC=test,DC=com",
			Trustee:    "S-1-5-21-1234-5678-9012-1200",
			AceType:    "ACCESS_ALLOWED",
			AccessMask: types.MaskGenericAll,
		},
	}
	domain := &types.DomainInfo{
		DomainName: "test.com",
		DomainSID:  "S-1-5-21-1234-5678-9012",
	}

	svc := NewAttackGraphService(users, groups, nil, acls, nil, domain, nil, nil, nil, nil, nil)
	export := svc.Export(500)

	require.NotEmpty(t, export.Paths)
	path := export.Paths[0]
	assert.Equal(t, types.PathACLAbuse, path.Type)
	assert.Equal(t, types.AttackRiskCritical, path.Risk, "1-hop GenericAll should be critical")
	assert.Equal(t, 1, path.Hops)
}

func TestAttackGraph_MultiHopPath(t *testing.T) {
	// User -> Group1 -> Group2 -> Domain Admins (3 hops from user, 2 from Group1, 1 from Group2)
	users := []types.User{
		{
			DN:             "CN=user1,CN=Users,DC=test,DC=com",
			SAMAccountName: "user1",
			ObjectSID:      "S-1-5-21-1234-5678-9012-1001",
			MemberOf:       []string{"CN=Group1,CN=Users,DC=test,DC=com"},
		},
	}
	groups := []types.Group{
		{
			DN:             "CN=Group1,CN=Users,DC=test,DC=com",
			SAMAccountName: "Group1",
			ObjectSID:      "S-1-5-21-1234-5678-9012-2001",
			MemberOf:       []string{"CN=Group2,CN=Users,DC=test,DC=com"},
		},
		{
			DN:             "CN=Group2,CN=Users,DC=test,DC=com",
			SAMAccountName: "Group2",
			ObjectSID:      "S-1-5-21-1234-5678-9012-2002",
			MemberOf:       []string{"CN=Domain Admins,CN=Users,DC=test,DC=com"},
		},
		{
			DN:             "CN=Domain Admins,CN=Users,DC=test,DC=com",
			SAMAccountName: "Domain Admins",
			ObjectSID:      "S-1-5-21-1234-5678-9012-512",
		},
	}
	domain := &types.DomainInfo{
		DomainName: "test.com",
		DomainSID:  "S-1-5-21-1234-5678-9012",
	}

	svc := NewAttackGraphService(users, groups, nil, nil, nil, domain, nil, nil, nil, nil, nil)
	export := svc.Export(500)

	// Should find 3 paths: Group2→DA (1 hop), Group1→Group2→DA (2 hops), user1→...→DA (3 hops)
	assert.Equal(t, 3, len(export.Paths), "groups should also be BFS sources")

	// Paths are sorted by risk then hops; shortest first within same risk
	// Find the 3-hop path from user1
	var found3Hop bool
	for _, p := range export.Paths {
		if p.Hops == 3 {
			found3Hop = true
			assert.Equal(t, types.PathGroupMembership, p.Type)
			assert.Equal(t, types.AttackRiskMedium, p.Risk, "3-hop membership should be medium")
		}
	}
	assert.True(t, found3Hop, "should find the 3-hop path from user1")
}

func TestAttackGraph_DisabledUserSkipped(t *testing.T) {
	// Disabled user should not be a source for attack paths
	users := []types.User{
		{
			DN:             "CN=disabled,CN=Users,DC=test,DC=com",
			SAMAccountName: "disabled",
			ObjectSID:      "S-1-5-21-1234-5678-9012-1001",
			Disabled:       true,
			MemberOf:       []string{"CN=Domain Admins,CN=Users,DC=test,DC=com"},
		},
	}
	groups := []types.Group{
		{
			DN:             "CN=Domain Admins,CN=Users,DC=test,DC=com",
			SAMAccountName: "Domain Admins",
			ObjectSID:      "S-1-5-21-1234-5678-9012-512",
		},
	}
	domain := &types.DomainInfo{
		DomainName: "test.com",
		DomainSID:  "S-1-5-21-1234-5678-9012",
	}

	svc := NewAttackGraphService(users, groups, nil, nil, nil, domain, nil, nil, nil, nil, nil)
	export := svc.Export(500)

	assert.Empty(t, export.Paths, "disabled users should not generate attack paths")
}

func TestAttackGraph_MaxPathsLimit(t *testing.T) {
	// Create many users all member of Domain Admins
	users := make([]types.User, 20)
	for i := range users {
		users[i] = types.User{
			DN:             "CN=user" + string(rune('A'+i)) + ",CN=Users,DC=test,DC=com",
			SAMAccountName: "user" + string(rune('A'+i)),
			ObjectSID:      "S-1-5-21-1234-5678-9012-" + padInt(1001+i),
			MemberOf:       []string{"CN=Domain Admins,CN=Users,DC=test,DC=com"},
		}
	}
	groups := []types.Group{
		{
			DN:             "CN=Domain Admins,CN=Users,DC=test,DC=com",
			SAMAccountName: "Domain Admins",
			ObjectSID:      "S-1-5-21-1234-5678-9012-512",
		},
	}
	domain := &types.DomainInfo{
		DomainName: "test.com",
		DomainSID:  "S-1-5-21-1234-5678-9012",
	}

	svc := NewAttackGraphService(users, groups, nil, nil, nil, domain, nil, nil, nil, nil, nil)
	export := svc.Export(5) // limit to 5

	assert.LessOrEqual(t, len(export.Paths), 5, "should respect maxPaths limit")
}

func TestAttackGraph_StatsComputation(t *testing.T) {
	users := []types.User{
		{
			DN:             "CN=user1,CN=Users,DC=test,DC=com",
			SAMAccountName: "user1",
			ObjectSID:      "S-1-5-21-1234-5678-9012-1001",
			MemberOf:       []string{"CN=Domain Admins,CN=Users,DC=test,DC=com"},
		},
		{
			DN:                    "CN=svc-sql,CN=Users,DC=test,DC=com",
			SAMAccountName:        "svc-sql",
			ObjectSID:             "S-1-5-21-1234-5678-9012-1002",
			ServicePrincipalNames: []string{"MSSQLSvc/sql01:1433"},
			MemberOf:              []string{"CN=Domain Admins,CN=Users,DC=test,DC=com"},
		},
	}
	groups := []types.Group{
		{
			DN:             "CN=Domain Admins,CN=Users,DC=test,DC=com",
			SAMAccountName: "Domain Admins",
			ObjectSID:      "S-1-5-21-1234-5678-9012-512",
		},
	}
	domain := &types.DomainInfo{
		DomainName: "test.com",
		DomainSID:  "S-1-5-21-1234-5678-9012",
	}

	svc := NewAttackGraphService(users, groups, nil, nil, nil, domain, nil, nil, nil, nil, nil)
	export := svc.Export(500)

	assert.Equal(t, len(export.Paths), export.Stats.TotalPaths)
	assert.NotEmpty(t, export.UniqueNodes, "should have unique nodes")

	// Both paths should be 1 hop
	assert.Equal(t, 1, export.Stats.ShortestPath)
	assert.Equal(t, 1, export.Stats.LongestPath)
	assert.Equal(t, float64(1), export.Stats.AverageHops)
}

func TestAttackGraph_PrivilegedTargets(t *testing.T) {
	groups := []types.Group{
		{
			DN:             "CN=Domain Admins,CN=Users,DC=test,DC=com",
			SAMAccountName: "Domain Admins",
			ObjectSID:      "S-1-5-21-1234-5678-9012-512",
		},
		{
			DN:             "CN=Enterprise Admins,CN=Users,DC=test,DC=com",
			SAMAccountName: "Enterprise Admins",
			ObjectSID:      "S-1-5-21-1234-5678-9012-519",
		},
		{
			DN:             "CN=Schema Admins,CN=Users,DC=test,DC=com",
			SAMAccountName: "Schema Admins",
			ObjectSID:      "S-1-5-21-1234-5678-9012-518",
		},
		{
			DN:             "CN=Regular Group,CN=Users,DC=test,DC=com",
			SAMAccountName: "Regular Group",
			ObjectSID:      "S-1-5-21-1234-5678-9012-3000",
		},
	}
	domain := &types.DomainInfo{
		DomainName: "test.com",
		DomainSID:  "S-1-5-21-1234-5678-9012",
	}

	svc := NewAttackGraphService(nil, groups, nil, nil, nil, domain, nil, nil, nil, nil, nil)

	// Should identify 3 domain privileged targets + well-known privileged targets (BUILTIN\Administrators etc.)
	// Domain targets: Domain Admins (-512), Enterprise Admins (-519), Schema Admins (-518)
	// Well-known: BUILTIN\Administrators (S-1-5-32-544) + others with privileged SID suffixes
	assert.Contains(t, svc.privilegedTargets, "S-1-5-21-1234-5678-9012-512")
	assert.Contains(t, svc.privilegedTargets, "S-1-5-21-1234-5678-9012-519")
	assert.Contains(t, svc.privilegedTargets, "S-1-5-21-1234-5678-9012-518")
	assert.NotContains(t, svc.privilegedTargets, "S-1-5-21-1234-5678-9012-3000")
}

func TestAttackGraph_DCSync(t *testing.T) {
	users := []types.User{
		{
			DN:             "CN=attacker,CN=Users,DC=test,DC=com",
			SAMAccountName: "attacker",
			ObjectSID:      "S-1-5-21-1234-5678-9012-1300",
		},
	}
	groups := []types.Group{
		{
			DN:             "CN=Domain Admins,CN=Users,DC=test,DC=com",
			SAMAccountName: "Domain Admins",
			ObjectSID:      "S-1-5-21-1234-5678-9012-512",
		},
	}
	acls := []types.ACLEntry{
		{
			ObjectDN:   "CN=Domain Admins,CN=Users,DC=test,DC=com",
			Trustee:    "S-1-5-21-1234-5678-9012-1300",
			AceType:    "ACCESS_ALLOWED",
			AccessMask: types.MaskControlAccess,
			ObjectType: types.GUIDDSReplicationGetChanges,
		},
	}
	domain := &types.DomainInfo{
		DomainName: "test.com",
		DomainSID:  "S-1-5-21-1234-5678-9012",
	}

	svc := NewAttackGraphService(users, groups, nil, acls, nil, domain, nil, nil, nil, nil, nil)
	export := svc.Export(500)

	require.NotEmpty(t, export.Paths)
	path := export.Paths[0]
	assert.Equal(t, types.PathDCSync, path.Type)
	assert.Equal(t, types.AttackRiskCritical, path.Risk, "DCSync should always be critical")
}

func TestAttackGraph_ASREPRoasting(t *testing.T) {
	users := []types.User{
		{
			DN:                 "CN=nopreauth,CN=Users,DC=test,DC=com",
			SAMAccountName:     "nopreauth",
			ObjectSID:          "S-1-5-21-1234-5678-9012-1400",
			UserAccountControl: types.UACDontRequirePreauth,
			MemberOf:           []string{"CN=Domain Admins,CN=Users,DC=test,DC=com"},
		},
	}
	groups := []types.Group{
		{
			DN:             "CN=Domain Admins,CN=Users,DC=test,DC=com",
			SAMAccountName: "Domain Admins",
			ObjectSID:      "S-1-5-21-1234-5678-9012-512",
		},
	}
	domain := &types.DomainInfo{
		DomainName: "test.com",
		DomainSID:  "S-1-5-21-1234-5678-9012",
	}

	svc := NewAttackGraphService(users, groups, nil, nil, nil, domain, nil, nil, nil, nil, nil)
	export := svc.Export(500)

	require.NotEmpty(t, export.Paths)
	path := export.Paths[0]
	assert.Equal(t, types.PathASREPRoasting, path.Type)
	assert.Contains(t, path.Mitigation, "pre-authentication")
}

func TestAttackGraph_OwnershipAbuse(t *testing.T) {
	// Non-privileged user owns a privileged group → OWNERSHIP_ABUSE path
	users := []types.User{
		{
			DN:             "CN=lowpriv,CN=Users,DC=test,DC=com",
			SAMAccountName: "lowpriv",
			ObjectSID:      "S-1-5-21-1234-5678-9012-1500",
		},
	}
	groups := []types.Group{
		{
			DN:             "CN=Domain Admins,CN=Users,DC=test,DC=com",
			SAMAccountName: "Domain Admins",
			ObjectSID:      "S-1-5-21-1234-5678-9012-512",
		},
	}
	owners := map[string]string{
		"CN=Domain Admins,CN=Users,DC=test,DC=com": "S-1-5-21-1234-5678-9012-1500",
	}
	domain := &types.DomainInfo{
		DomainName: "test.com",
		DomainSID:  "S-1-5-21-1234-5678-9012",
	}

	svc := NewAttackGraphService(users, groups, nil, nil, owners, domain, nil, nil, nil, nil, nil)
	export := svc.Export(500)

	require.NotEmpty(t, export.Paths, "should find ownership abuse path")
	path := export.Paths[0]
	assert.Equal(t, types.PathOwnershipAbuse, path.Type)
	assert.Equal(t, types.AttackRiskCritical, path.Risk, "1-hop ownership of DA should be critical")
	assert.Equal(t, 1, path.Hops)
	assert.Contains(t, path.Description, "owns")
	assert.Contains(t, path.Mitigation, "ownership")
}

func TestAttackGraph_OwnershipSkipExpected(t *testing.T) {
	// Domain Admins owning objects is expected → no path
	users := []types.User{
		{
			DN:             "CN=normaluser,CN=Users,DC=test,DC=com",
			SAMAccountName: "normaluser",
			ObjectSID:      "S-1-5-21-1234-5678-9012-1600",
		},
	}
	groups := []types.Group{
		{
			DN:             "CN=Domain Admins,CN=Users,DC=test,DC=com",
			SAMAccountName: "Domain Admins",
			ObjectSID:      "S-1-5-21-1234-5678-9012-512",
		},
	}
	owners := map[string]string{
		// Domain Admins owns normaluser → expected, not abusable
		"CN=normaluser,CN=Users,DC=test,DC=com": "S-1-5-21-1234-5678-9012-512",
	}
	domain := &types.DomainInfo{
		DomainName: "test.com",
		DomainSID:  "S-1-5-21-1234-5678-9012",
	}

	svc := NewAttackGraphService(users, groups, nil, nil, owners, domain, nil, nil, nil, nil, nil)
	export := svc.Export(500)

	// No ownership abuse paths (DA owning things is normal)
	for _, p := range export.Paths {
		assert.NotEqual(t, types.PathOwnershipAbuse, p.Type,
			"Domain Admins owning objects should not generate ownership abuse paths")
	}
}

func TestAttackGraph_GPOAbuseViaOU(t *testing.T) {
	// Attack path: attacker → WriteDACL on GPO → GPO linked to OU → OU contains DC
	users := []types.User{
		{
			DN:             "CN=attacker,OU=IT,DC=test,DC=com",
			SAMAccountName: "attacker",
			ObjectSID:      "S-1-5-21-1234-5678-9012-1700",
		},
	}
	groups := []types.Group{
		{
			DN:             "CN=Domain Admins,CN=Users,DC=test,DC=com",
			SAMAccountName: "Domain Admins",
			ObjectSID:      "S-1-5-21-1234-5678-9012-512",
		},
	}
	computers := []types.Computer{
		{
			DN:             "CN=DC01,OU=DomainControllers,DC=test,DC=com",
			SAMAccountName: "DC01$",
			ObjectSID:      "S-1-5-21-1234-5678-9012-1000",
			MemberOf:       []string{"CN=Domain Controllers,CN=Users,DC=test,DC=com"},
			AdminCount:     true,
		},
	}
	ous := []types.OU{
		{
			DN:   "OU=DomainControllers,DC=test,DC=com",
			Name: "DomainControllers",
		},
	}
	gpos := []types.GPO{
		{
			DN:          "CN={GPO-GUID},CN=Policies,CN=System,DC=test,DC=com",
			CN:          "{GPO-GUID}",
			DisplayName: "Server Policy",
			Enabled:     true,
		},
	}
	gpoLinks := []GPOLink{
		{
			GPOCN:       "{GPO-GUID}",
			LinkedTo:    "OU=DomainControllers,DC=test,DC=com",
			LinkEnabled: true,
		},
	}
	gpoAcls := []GPOAcl{
		{
			GPODN:      "CN={GPO-GUID},CN=Policies,CN=System,DC=test,DC=com",
			TrusteeSID: "S-1-5-21-1234-5678-9012-1700", // attacker
			AccessMask: types.MaskWriteDACL,
			AceType:    "ACCESS_ALLOWED",
		},
	}
	domain := &types.DomainInfo{
		DomainName: "test.com",
		DomainSID:  "S-1-5-21-1234-5678-9012",
		DomainDN:   "DC=test,DC=com",
	}

	svc := NewAttackGraphService(users, groups, computers, nil, nil, domain, ous, gpos, gpoLinks, gpoAcls, nil)
	export := svc.Export(500)

	// Should find GPO abuse path: attacker → WriteDACL → GPO → GPLink → OU → Contains → DC01
	var foundGPOPath bool
	for _, p := range export.Paths {
		if p.EntryPoint.Name == "attacker" && p.Target.Name == "DC01$" {
			foundGPOPath = true
			assert.Equal(t, types.PathACLAbuse, p.Type, "GPO abuse should be classified as ACL_ABUSE")
			assert.Equal(t, 3, p.Hops, "should be 3 hops: attacker→GPO→OU→DC01")
			break
		}
	}
	assert.True(t, foundGPOPath, "should find GPO abuse path from attacker to DC01 via GPO+OU")
}

func TestAttackGraph_OUContainsEdges(t *testing.T) {
	// User with GenericAll on OU → OU contains privileged group
	users := []types.User{
		{
			DN:             "CN=attacker,CN=Users,DC=test,DC=com",
			SAMAccountName: "attacker",
			ObjectSID:      "S-1-5-21-1234-5678-9012-1800",
		},
	}
	groups := []types.Group{
		{
			DN:             "CN=Domain Admins,OU=AdminGroups,DC=test,DC=com",
			SAMAccountName: "Domain Admins",
			ObjectSID:      "S-1-5-21-1234-5678-9012-512",
		},
	}
	ous := []types.OU{
		{
			DN:   "OU=AdminGroups,DC=test,DC=com",
			Name: "AdminGroups",
		},
	}
	acls := []types.ACLEntry{
		{
			ObjectDN:   "OU=AdminGroups,DC=test,DC=com",
			Trustee:    "S-1-5-21-1234-5678-9012-1800",
			AceType:    "ACCESS_ALLOWED",
			AccessMask: types.MaskGenericAll,
		},
	}
	domain := &types.DomainInfo{
		DomainName: "test.com",
		DomainSID:  "S-1-5-21-1234-5678-9012",
		DomainDN:   "DC=test,DC=com",
	}

	svc := NewAttackGraphService(users, groups, nil, acls, nil, domain, ous, nil, nil, nil, nil)
	export := svc.Export(500)

	// Should find: attacker → GenericAll → OU → Contains → Domain Admins
	var foundOUPath bool
	for _, p := range export.Paths {
		if p.EntryPoint.Name == "attacker" && p.Target.Name == "Domain Admins" {
			foundOUPath = true
			assert.Equal(t, types.PathACLAbuse, p.Type)
			assert.Equal(t, 2, p.Hops, "should be 2 hops: attacker→OU→DA")
			break
		}
	}
	assert.True(t, foundOUPath, "should find path from attacker to DA via OU containment")
}

func TestAttackGraph_SIDHistory(t *testing.T) {
	// User with SIDHistory containing Domain Admins SID → SID_HISTORY path
	users := []types.User{
		{
			DN:             "CN=migrated,CN=Users,DC=test,DC=com",
			SAMAccountName: "migrated",
			ObjectSID:      "S-1-5-21-1234-5678-9012-1900",
			SIDHistory:     []string{"S-1-5-21-1234-5678-9012-512"}, // DA SID
		},
	}
	groups := []types.Group{
		{
			DN:             "CN=Domain Admins,CN=Users,DC=test,DC=com",
			SAMAccountName: "Domain Admins",
			ObjectSID:      "S-1-5-21-1234-5678-9012-512",
		},
	}
	domain := &types.DomainInfo{
		DomainName: "test.com",
		DomainSID:  "S-1-5-21-1234-5678-9012",
	}

	svc := NewAttackGraphService(users, groups, nil, nil, nil, domain, nil, nil, nil, nil, nil)
	export := svc.Export(500)

	require.NotEmpty(t, export.Paths, "should find SID history path")
	var foundSIDHistory bool
	for _, p := range export.Paths {
		if p.Type == types.PathSIDHistory && p.EntryPoint.Name == "migrated" {
			foundSIDHistory = true
			assert.Equal(t, types.AttackRiskCritical, p.Risk, "SID history should always be critical")
			assert.Equal(t, 1, p.Hops)
			assert.Contains(t, p.Description, "SID history")
			assert.Contains(t, p.Mitigation, "cleanSIDHistory")
			break
		}
	}
	assert.True(t, foundSIDHistory, "should find SID_HISTORY path from migrated to Domain Admins")
}

func TestAttackGraph_ReadLAPSPassword(t *testing.T) {
	// User with ControlAccess+GUIDLAPSPassword on a computer with LAPS
	users := []types.User{
		{
			DN:             "CN=helpdesk,CN=Users,DC=test,DC=com",
			SAMAccountName: "helpdesk",
			ObjectSID:      "S-1-5-21-1234-5678-9012-2000",
		},
	}
	groups := []types.Group{
		{
			DN:             "CN=Domain Admins,CN=Users,DC=test,DC=com",
			SAMAccountName: "Domain Admins",
			ObjectSID:      "S-1-5-21-1234-5678-9012-512",
		},
	}
	computers := []types.Computer{
		{
			DN:             "CN=DC01,OU=DomainControllers,DC=test,DC=com",
			SAMAccountName: "DC01$",
			ObjectSID:      "S-1-5-21-1234-5678-9012-1000",
			MemberOf:       []string{"CN=Domain Controllers,CN=Users,DC=test,DC=com"},
			AdminCount:     true,
			HasLegacyLAPS:  true,
		},
	}
	acls := []types.ACLEntry{
		{
			ObjectDN:   "CN=DC01,OU=DomainControllers,DC=test,DC=com",
			Trustee:    "S-1-5-21-1234-5678-9012-2000",
			AceType:    "ACCESS_ALLOWED",
			AccessMask: types.MaskControlAccess,
			ObjectType: types.GUIDLAPSPassword,
		},
	}
	domain := &types.DomainInfo{
		DomainName: "test.com",
		DomainSID:  "S-1-5-21-1234-5678-9012",
	}

	svc := NewAttackGraphService(users, groups, computers, acls, nil, domain, nil, nil, nil, nil, nil)
	export := svc.Export(500)

	require.NotEmpty(t, export.Paths, "should find LAPS abuse path")
	var foundLAPS bool
	for _, p := range export.Paths {
		if p.Type == types.PathLAPSAbuse && p.EntryPoint.Name == "helpdesk" {
			foundLAPS = true
			assert.Equal(t, types.AttackRiskCritical, p.Risk)
			assert.Contains(t, p.Description, "LAPS")
			break
		}
	}
	assert.True(t, foundLAPS, "should find LAPS_ABUSE path from helpdesk to DC01")
}

func TestAttackGraph_WriteKeyCredentialLink(t *testing.T) {
	// User with WriteProperty+GUIDKeyCredentialLink on admin user → ACL_ABUSE (shadow credentials)
	users := []types.User{
		{
			DN:             "CN=attacker,CN=Users,DC=test,DC=com",
			SAMAccountName: "attacker",
			ObjectSID:      "S-1-5-21-1234-5678-9012-2100",
		},
		{
			DN:             "CN=admin,CN=Users,DC=test,DC=com",
			SAMAccountName: "admin",
			ObjectSID:      "S-1-5-21-1234-5678-9012-500",
			AdminCount:     true,
		},
	}
	groups := []types.Group{
		{
			DN:             "CN=Domain Admins,CN=Users,DC=test,DC=com",
			SAMAccountName: "Domain Admins",
			ObjectSID:      "S-1-5-21-1234-5678-9012-512",
		},
	}
	acls := []types.ACLEntry{
		{
			ObjectDN:   "CN=admin,CN=Users,DC=test,DC=com",
			Trustee:    "S-1-5-21-1234-5678-9012-2100",
			AceType:    "ACCESS_ALLOWED",
			AccessMask: types.MaskWriteProperty,
			ObjectType: types.GUIDKeyCredentialLink,
		},
	}
	domain := &types.DomainInfo{
		DomainName: "test.com",
		DomainSID:  "S-1-5-21-1234-5678-9012",
	}

	svc := NewAttackGraphService(users, groups, nil, acls, nil, domain, nil, nil, nil, nil, nil)
	export := svc.Export(500)

	require.NotEmpty(t, export.Paths, "should find shadow credentials path")
	var foundShadowCred bool
	for _, p := range export.Paths {
		if p.EntryPoint.Name == "attacker" {
			foundShadowCred = true
			assert.Equal(t, types.PathACLAbuse, p.Type, "shadow credentials falls under ACL_ABUSE")
			assert.Equal(t, types.AttackRiskCritical, p.Risk, "1-hop WriteKeyCredentialLink should be critical")
			break
		}
	}
	assert.True(t, foundShadowCred, "should find shadow credentials path from attacker to admin")
}

func TestAttackGraph_ReadGMSAPassword(t *testing.T) {
	// Build a minimal security descriptor with 1 ACCESS_ALLOWED ACE containing helpdesk SID
	// SID: S-1-5-21-1234-5678-9012-2000
	// Revision=1, SubAuthorityCount=5, Authority=5 (NT Authority)
	// SubAuthorities: 21, 1234, 5678, 9012, 2000
	sid := []byte{
		0x01,                               // Revision
		0x05,                               // SubAuthorityCount
		0x00, 0x00, 0x00, 0x00, 0x00, 0x05, // Authority (big-endian 5)
	}
	// SubAuthorities (little-endian uint32s)
	subAuths := []uint32{21, 1234, 5678, 9012, 2000}
	for _, sa := range subAuths {
		b := make([]byte, 4)
		binary.LittleEndian.PutUint32(b, sa)
		sid = append(sid, b...)
	}

	// ACE: ACCESS_ALLOWED (type=0x00), size = 8 (header) + len(sid)
	aceSize := 8 + len(sid)
	ace := []byte{
		0x00,                                              // ACE type: ACCESS_ALLOWED
		0x00,                                              // ACE flags
		byte(aceSize & 0xFF), byte((aceSize >> 8) & 0xFF), // ACE size (LE)
		0xFF, 0x01, 0x0F, 0x00, // Access mask (placeholder)
	}
	ace = append(ace, sid...)

	// ACL header: revision=2, size, ace_count=1
	aclSize := 8 + len(ace)
	acl := []byte{
		0x02,                                              // ACL revision
		0x00,                                              // Sbz1
		byte(aclSize & 0xFF), byte((aclSize >> 8) & 0xFF), // ACL size (LE)
		0x01, 0x00, // ACE count (LE)
		0x00, 0x00, // Sbz2
	}
	acl = append(acl, ace...)

	// Security descriptor header (20 bytes min)
	// Offset 0: Revision=1
	// Offset 1: Sbz1
	// Offset 2-3: Control flags (SE_DACL_PRESENT = 0x0004)
	// Offset 4-7: OffsetOwner (0)
	// Offset 8-11: OffsetGroup (0)
	// Offset 12-15: OffsetSacl (0)
	// Offset 16-19: OffsetDacl (20 = right after header)
	sd := make([]byte, 20)
	sd[0] = 0x01                                   // Revision
	binary.LittleEndian.PutUint16(sd[2:4], 0x0004) // Control: SE_DACL_PRESENT
	binary.LittleEndian.PutUint32(sd[16:20], 20)   // DACL offset
	sd = append(sd, acl...)

	users := []types.User{
		{
			DN:             "CN=helpdesk,CN=Users,DC=test,DC=com",
			SAMAccountName: "helpdesk",
			ObjectSID:      "S-1-5-21-1234-5678-9012-2000",
		},
		{
			DN:             "CN=svc-sql,CN=Users,DC=test,DC=com",
			SAMAccountName: "svc-sql",
			ObjectSID:      "S-1-5-21-1234-5678-9012-2200",
			IsGMSA:         true,
			GMSAMembership: sd,
			MemberOf:       []string{"CN=Domain Admins,CN=Users,DC=test,DC=com"},
		},
	}
	groups := []types.Group{
		{
			DN:             "CN=Domain Admins,CN=Users,DC=test,DC=com",
			SAMAccountName: "Domain Admins",
			ObjectSID:      "S-1-5-21-1234-5678-9012-512",
		},
	}
	domain := &types.DomainInfo{
		DomainName: "test.com",
		DomainSID:  "S-1-5-21-1234-5678-9012",
	}

	svc := NewAttackGraphService(users, groups, nil, nil, nil, domain, nil, nil, nil, nil, nil)
	export := svc.Export(500)

	require.NotEmpty(t, export.Paths, "should find gMSA abuse path")
	var foundGMSA bool
	for _, p := range export.Paths {
		if p.Type == types.PathGMSAAbuse && p.EntryPoint.Name == "helpdesk" {
			foundGMSA = true
			assert.Contains(t, p.Description, "gMSA")
			assert.Contains(t, p.Mitigation, "GroupMSAMembership")
			break
		}
	}
	assert.True(t, foundGMSA, "should find GMSA_ABUSE path from helpdesk via svc-sql to Domain Admins")
}

func TestAttackGraph_CertificateAbuse(t *testing.T) {
	// User with enrollment rights on ESC1-vulnerable cert template → CERTIFICATE_ABUSE
	users := []types.User{
		{
			DN:             "CN=lowpriv,CN=Users,DC=test,DC=com",
			SAMAccountName: "lowpriv",
			ObjectSID:      "S-1-5-21-1234-5678-9012-2300",
		},
	}
	groups := []types.Group{
		{
			DN:             "CN=Domain Admins,CN=Users,DC=test,DC=com",
			SAMAccountName: "Domain Admins",
			ObjectSID:      "S-1-5-21-1234-5678-9012-512",
		},
	}
	certTemplates := []types.CertTemplate{
		{
			DN:               "CN=VulnTemplate,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=test,DC=com",
			Name:             "VulnTemplate",
			SubjectNameFlag:  0x01,                          // CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT
			ExtendedKeyUsage: []string{"1.3.6.1.5.5.7.3.2"}, // Client Authentication
		},
	}
	acls := []types.ACLEntry{
		{
			ObjectDN:   "CN=VulnTemplate,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=test,DC=com",
			Trustee:    "S-1-5-21-1234-5678-9012-2300",
			AceType:    "ACCESS_ALLOWED",
			AccessMask: types.MaskControlAccess,
			ObjectType: types.GUIDCertificateEnrollment,
		},
	}
	domain := &types.DomainInfo{
		DomainName: "test.com",
		DomainSID:  "S-1-5-21-1234-5678-9012",
		DomainDN:   "DC=test,DC=com",
	}

	svc := NewAttackGraphService(users, groups, nil, acls, nil, domain, nil, nil, nil, nil, certTemplates)
	export := svc.Export(500)

	require.NotEmpty(t, export.Paths, "should find certificate abuse path")
	var foundCert bool
	for _, p := range export.Paths {
		if p.Type == types.PathCertAbuse && p.EntryPoint.Name == "lowpriv" {
			foundCert = true
			assert.Equal(t, types.AttackRiskCritical, p.Risk, "cert abuse should be critical")
			assert.Contains(t, p.Description, "certificate")
			break
		}
	}
	assert.True(t, foundCert, "should find CERTIFICATE_ABUSE path from lowpriv via VulnTemplate")
}

func TestAttackGraph_CertTemplateNotVulnerable(t *testing.T) {
	// Template that requires manager approval → NOT vulnerable to ESC1
	users := []types.User{
		{
			DN:             "CN=lowpriv,CN=Users,DC=test,DC=com",
			SAMAccountName: "lowpriv",
			ObjectSID:      "S-1-5-21-1234-5678-9012-2400",
		},
	}
	groups := []types.Group{
		{
			DN:             "CN=Domain Admins,CN=Users,DC=test,DC=com",
			SAMAccountName: "Domain Admins",
			ObjectSID:      "S-1-5-21-1234-5678-9012-512",
		},
	}
	certTemplates := []types.CertTemplate{
		{
			DN:                      "CN=SafeTemplate,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=test,DC=com",
			Name:                    "SafeTemplate",
			SubjectNameFlag:         0x01,
			ExtendedKeyUsage:        []string{"1.3.6.1.5.5.7.3.2"},
			RequiresManagerApproval: true, // NOT vulnerable
		},
	}
	acls := []types.ACLEntry{
		{
			ObjectDN:   "CN=SafeTemplate,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=test,DC=com",
			Trustee:    "S-1-5-21-1234-5678-9012-2400",
			AceType:    "ACCESS_ALLOWED",
			AccessMask: types.MaskControlAccess,
			ObjectType: types.GUIDCertificateEnrollment,
		},
	}
	domain := &types.DomainInfo{
		DomainName: "test.com",
		DomainSID:  "S-1-5-21-1234-5678-9012",
		DomainDN:   "DC=test,DC=com",
	}

	svc := NewAttackGraphService(users, groups, nil, acls, nil, domain, nil, nil, nil, nil, certTemplates)
	export := svc.Export(500)

	// Should NOT find certificate abuse path (template requires approval)
	for _, p := range export.Paths {
		assert.NotEqual(t, types.PathCertAbuse, p.Type,
			"template with manager approval should not generate certificate abuse paths")
	}
}

// padInt returns a string representation with enough digits
func padInt(n int) string {
	return fmt.Sprintf("%d", n)
}

// TestAttackGraph_ExportIsDeterministic covers T_046/B_048: node building and
// edge construction range s.nodes (a map) throughout this file. 25 users all
// hold GenericAll on Domain Admins directly — one hop, identical risk, so
// selectPaths' 20-per-target cap (maxPathsPerTarget) has to choose which 20
// of the 25 tied candidates survive, and sort.Slice's tie order depends on
// the order candidates were built in. Building the graph fresh from
// identical input several times must give byte-identical paths every time —
// not just the same paths in a different order, but the same SURVIVING
// subset under the cap.
func TestAttackGraph_ExportIsDeterministic(t *testing.T) {
	const domainDN = "DC=example,DC=com"
	var users []types.User
	for i := 25; i >= 1; i-- { // reverse-alphabetical build order
		users = append(users, types.User{
			DN:             fmt.Sprintf("CN=attacker-%02d,CN=Users,%s", i, domainDN),
			SAMAccountName: fmt.Sprintf("attacker-%02d", i),
			ObjectSID:      fmt.Sprintf("S-1-5-21-1234567890-1111111111-2222222222-%d", 20000+i),
		})
	}
	groups := []types.Group{{
		DN:             "CN=Domain Admins,CN=Users," + domainDN,
		SAMAccountName: "Domain Admins",
		ObjectSID:      "S-1-5-21-1234567890-1111111111-2222222222-512",
	}}
	var acls []types.ACLEntry
	for _, u := range users {
		acls = append(acls, types.ACLEntry{
			ObjectDN:   "CN=Domain Admins,CN=Users," + domainDN,
			Trustee:    u.ObjectSID,
			AceType:    "ACCESS_ALLOWED",
			AccessMask: types.MaskGenericAll,
		})
	}
	domain := &types.DomainInfo{
		DomainName: "example",
		DomainSID:  "S-1-5-21-1234567890-1111111111-2222222222",
		DomainDN:   domainDN,
	}

	build := func() []string {
		svc := NewAttackGraphService(users, groups, nil, acls, nil, domain, nil, nil, nil, nil, nil)
		export := svc.Export(500)
		ids := make([]string, len(export.Paths))
		for i, p := range export.Paths {
			ids[i] = p.EntryPoint.ID
		}
		return ids
	}

	first := build()
	require.Len(t, first, 20, "25 tied candidates capped to maxPathsPerTarget=20")
	for i := 0; i < 9; i++ {
		assert.Equal(t, first, build(), "run %d: attack graph export not deterministic across identical builds", i)
	}
}
