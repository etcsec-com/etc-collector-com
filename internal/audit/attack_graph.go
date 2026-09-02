// Package audit provides the attack graph analysis system for Active Directory privilege escalation detection.
//
// # Attack Graph Analysis System
//
// This module implements Active Directory privilege escalation path detection using breadth-first search (BFS)
// to find shortest paths from unprivileged principals (users, groups, computers) to privileged targets
// (Domain Admins, Domain Controllers, Schema Admins, etc.).
//
// Core Algorithm:
//  1. Build directed graph with nodes (users/groups/computers) and edges (membership/ACL/delegation relationships)
//  2. Identify privileged targets by SID suffix (e.g., S-1-5-21-<domain>-512 = Domain Admins), adminCount=1, or name
//  3. Run BFS from each non-privileged node to find shortest paths to any privileged target
//  4. Calculate risk score based on: path length, relation types (abusable ACL permissions), and target privilege level
//  5. Classify paths by attack type: Kerberoasting, AS-REP Roasting, DCSync, ACL abuse, delegation abuse, etc.
//
// Data Structures:
//   - internalNode: Graph node representing AD object with security attributes (UAC flags, SID, delegation settings)
//   - internalEdge: Directed edge with relation type (MemberOf, WriteOwner, DCSync, ForceChangePassword, etc.)
//   - bfsPath: BFS traversal result containing node sequence and edges
//   - AttackGraphService: Main service orchestrating graph building, BFS execution, and path export
//
// Graph Building Process:
//  1. addUserNodes()     - Create nodes for all users with security attributes
//  2. addGroupNodes()    - Create nodes for all groups with privilege classification
//  3. addComputerNodes() - Create nodes for all computers, marking DCs as privileged
//  4. addMembershipEdges() - Create edges for group memberships (MemberOf relations)
//  5. addACLEdges()      - Create edges for dangerous ACL permissions (GenericAll, WriteDACL, DCSync, etc.)
//  6. addDelegationEdges() - Create edges for Kerberos delegation (constrained/unconstrained)
//  7. identifyPrivilegedTargets() - Mark nodes as privileged targets based on SID/adminCount/name
//
// BFS Path Finding:
//   - Explores from each non-privileged, enabled node
//   - Stops at first privileged target found (shortest path guarantee)
//   - Enforces 6-hop maximum to prevent performance issues on large graphs
//   - Tracks visited nodes to prevent cycles
//   - Returns immediately when privileged target reached (early termination optimization)
//
// Risk Scoring:
//   - Critical: DCSync paths, short paths (≤2 hops) with abusable ACL permissions
//   - High: Delegation abuse paths, short paths (≤2 hops) without abusable ACLs
//   - Medium: Medium-length paths (3-4 hops)
//   - Low: Long paths (5-6 hops)
//
// Attack Path Types:
//   - Kerberoasting: User has SPN, can be offline cracked
//   - AS-REP Roasting: User lacks Kerberos pre-auth, can be offline cracked
//   - DCSync: Principal has replication rights (DS-Replication-Get-Changes + DS-Replication-Get-Changes-All)
//   - Delegation Abuse: Constrained/unconstrained Kerberos delegation to privileged targets
//   - ACL Abuse: Generic permissions (GenericAll, WriteDACL, WriteOwner, GenericWrite)
//   - Group Membership: Pure nested group membership chains
//   - Ownership Abuse: Object ownership allowing control
//
// References:
//   - BloodHound methodology: https://github.com/BloodHoundAD/BloodHound
//   - Attack path scoring based on MITRE ATT&CK techniques
//   - MS-ADTS: Active Directory Technical Specification
//   - MS-DTYP: Windows Data Types (for ACL bitmasks)
//
// Performance Considerations:
//   - Graph size: O(U + G + C) nodes where U=users, G=groups, C=computers
//   - Edge complexity: O(M + A + D) where M=memberships, A=ACLs, D=delegations
//   - BFS per source: O(V + E) typical case, where V=nodes, E=edges
//   - Max paths limit prevents excessive memory usage (default 500 paths)
//   - 6-hop limit prevents exponential exploration on highly connected graphs
package audit

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/etcsec-com/etc-collector/pkg/types"
)

// internalNode represents a node in the graph with metadata for BFS
type internalNode struct {
	id           string
	dn           string
	name         string
	nodeType     types.AttackNodeType
	sid          string
	isEnabled    bool
	isPrivileged bool
	adminCount   bool
	memberOf     []string // DNs of parent groups
	spn          []string
	uac          int
	delegateTo   []string
	rbcdFrom     []string
	// New attack path fields
	sidHistory               []string
	hasLAPS                  bool
	isGMSA                   bool
	gmsaTrustees             []string
	isVulnerableCertTemplate bool
}

// internalEdge represents a directed edge in the graph
type internalEdge struct {
	source     string
	target     string
	relation   types.AttackRelationType
	accessMask int
	objectType string
	isAbusable bool
}

// bfsPath is a BFS shortest path result
type bfsPath struct {
	nodes []string       // node IDs in order
	edges []internalEdge // edges between consecutive nodes
}

// wellKnownSecurityPrincipals maps security-relevant well-known SIDs to display names.
// Only includes SIDs that matter for privilege escalation analysis (can be ACL trustees
// with dangerous permissions that chain to domain compromise).
var wellKnownSecurityPrincipals = map[string]string{
	"S-1-1-0":      "Everyone",
	"S-1-5-11":     "Authenticated Users",
	"S-1-5-32-544": "BUILTIN\\Administrators",
	"S-1-5-32-545": "BUILTIN\\Users",
	"S-1-5-32-548": "BUILTIN\\Account Operators",
	"S-1-5-32-549": "BUILTIN\\Server Operators",
	"S-1-5-32-550": "BUILTIN\\Print Operators",
	"S-1-5-32-551": "BUILTIN\\Backup Operators",
}

// pathTypeCaps limits the number of paths per attack type in the output.
// Higher caps for more critical/actionable types.
var pathTypeCaps = map[types.AttackPathType]int{
	types.PathDCSync:          30,
	types.PathDelegationAbuse: 30,
	types.PathACLAbuse:        50,
	types.PathKerberoasting:   40,
	types.PathASREPRoasting:   30,
	types.PathOwnershipAbuse:  20,
	types.PathGroupMembership: 50,
	types.PathSIDHistory:      30,
	types.PathLAPSAbuse:       30,
	types.PathGMSAAbuse:       20,
	types.PathCertAbuse:       30,
}

// maxPathsPerTarget limits paths to the same privileged target to ensure diversity.
const maxPathsPerTarget = 20

// AttackGraphService builds and exports attack path data using BFS
type AttackGraphService struct {
	nodes             map[string]*internalNode
	edges             map[string][]internalEdge // source -> outgoing edges
	privilegedTargets map[string]types.AttackTarget
	dnToID            map[string]string // lowercase DN -> node ID
	sidToID           map[string]string // SID -> node ID (for nodes where key != SID)
	gpoCNToID         map[string]string // GPO CN (GUID) -> node ID (for GPOLink resolution)
	dcNodeIDs         []string          // Domain Controller node IDs for unconstrained delegation edges
	domainSID         string
	domainName        string
	domainDN          string
}

// NewAttackGraphService creates a new attack graph service and builds the graph.
// OUs, GPOs, GPOLinks and GPOAcls are optional; pass nil when not available.
func NewAttackGraphService(
	users []types.User,
	groups []types.Group,
	computers []types.Computer,
	aclEntries []types.ACLEntry,
	objectOwners map[string]string,
	domain *types.DomainInfo,
	ous []types.OU,
	gpos []types.GPO,
	gpoLinks []GPOLink,
	gpoAcls []GPOAcl,
	certTemplates []types.CertTemplate,
) *AttackGraphService {
	s := &AttackGraphService{
		nodes:             make(map[string]*internalNode),
		edges:             make(map[string][]internalEdge),
		privilegedTargets: make(map[string]types.AttackTarget),
		dnToID:            make(map[string]string),
		sidToID:           make(map[string]string),
		gpoCNToID:         make(map[string]string),
	}
	if domain != nil {
		s.domainName = domain.DomainName
		s.domainSID = domain.DomainSID
		s.domainDN = domain.DomainDN
		if s.domainDN == "" {
			s.domainDN = domain.DN
		}
	}

	// Extract domain SID from users if not provided
	if s.domainSID == "" {
		s.domainSID = s.extractDomainSID(users)
	}

	// Build graph: nodes
	s.addDomainNode(domain)
	s.addUserNodes(users)
	s.addGroupNodes(groups)
	s.addComputerNodes(computers)
	s.addOUNodes(ous)
	s.addGPONodes(gpos)
	s.addCertTemplateNodes(certTemplates)
	s.addWellKnownNodes()

	// Build graph: edges
	s.addMembershipEdges()
	s.addSIDHistoryEdges()
	s.addACLEdges(aclEntries)
	s.addOwnershipEdges(objectOwners)
	s.addDelegationEdges()
	s.addGMSAEdges()
	s.addContainsEdges()
	s.addGPLinkEdges(gpoLinks)
	s.addGPOACLEdges(gpoAcls)
	s.addCertAbuseEdges()
	s.identifyPrivilegedTargets()

	return s
}

// Export runs BFS and returns the full attack graph export
func (s *AttackGraphService) Export(maxPaths int) *types.AttackGraphExport {
	paths, totalCandidates, candidatesByType := s.findAllAttackPaths(maxPaths)
	stats := s.computeStats(paths, totalCandidates, candidatesByType)
	uniqueNodes := s.getUniqueNodes(paths)

	targets := make([]types.AttackTarget, 0, len(s.privilegedTargets))
	targetIDs := make([]string, 0, len(s.privilegedTargets))
	for id := range s.privilegedTargets {
		targetIDs = append(targetIDs, id)
	}
	sort.Strings(targetIDs)
	for _, id := range targetIDs {
		targets = append(targets, s.privilegedTargets[id])
	}

	return &types.AttackGraphExport{
		Version:     "1.0",
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Domain:      s.domainName,
		Targets:     targets,
		Paths:       paths,
		Stats:       stats,
		UniqueNodes: uniqueNodes,
	}
}

// --- Node building ---

// addDomainNode creates a node for the domain root object.
// This is critical because DCSync ACEs target the domain root DN (e.g., DC=corp,DC=com).
// Without this node, dnToID has no entry for the domain root and all DCSync edges are dropped.
func (s *AttackGraphService) addDomainNode(domain *types.DomainInfo) {
	if domain == nil {
		return
	}
	domainDN := domain.DomainDN
	if domainDN == "" {
		domainDN = domain.DN
	}
	if domainDN == "" {
		return
	}

	id := domain.DomainSID
	if id == "" {
		id = s.generateID(domainDN)
	}

	s.nodes[id] = &internalNode{
		id:           id,
		dn:           domainDN,
		name:         domain.DomainName,
		nodeType:     types.AttackNodeDomain,
		sid:          domain.DomainSID,
		isEnabled:    true,
		isPrivileged: true,
	}
	s.dnToID[strings.ToLower(domainDN)] = id

	s.privilegedTargets[id] = types.AttackTarget{
		ID:     id,
		Name:   domain.DomainName,
		Type:   types.AttackNodeDomain,
		SID:    domain.DomainSID,
		DN:     domainDN,
		Reason: "Domain Root",
	}
}

// addWellKnownNodes creates synthetic nodes for well-known security principals.
// These SIDs appear as ACE trustees but have no corresponding AD object in the collection.
// Without these nodes, ACL edges from Everyone, Authenticated Users, etc. are silently dropped.
func (s *AttackGraphService) addWellKnownNodes() {
	for sid, name := range wellKnownSecurityPrincipals {
		if _, exists := s.nodes[sid]; exists {
			continue
		}

		isPriv := sid == "S-1-5-32-544" // BUILTIN\Administrators

		s.nodes[sid] = &internalNode{
			id:           sid,
			name:         name,
			nodeType:     types.AttackNodeGroup,
			sid:          sid,
			isEnabled:    true,
			isPrivileged: isPriv,
		}

		if isPriv {
			s.privilegedTargets[sid] = types.AttackTarget{
				ID:     sid,
				Name:   name,
				Type:   types.AttackNodeGroup,
				SID:    sid,
				Reason: "Built-in Administrators",
			}
		}
	}
}

// addUserNodes creates graph nodes for all user accounts with security-relevant attributes.
// Each user becomes a node with: SID, enabled status, adminCount, group memberships, SPNs,
// UAC flags, and delegation settings. Users with adminCount=1 are marked as privileged.
func (s *AttackGraphService) addUserNodes(users []types.User) {
	for i := range users {
		u := &users[i]
		id := u.ObjectSID
		if id == "" {
			id = s.generateID(u.DN)
		}

		node := &internalNode{
			id:           id,
			dn:           u.DN,
			name:         u.SAMAccountName,
			nodeType:     types.AttackNodeUser,
			sid:          u.ObjectSID,
			isEnabled:    !u.Disabled,
			isPrivileged: u.AdminCount,
			adminCount:   u.AdminCount,
			memberOf:     u.MemberOf,
			spn:          u.ServicePrincipalNames,
			uac:          u.UserAccountControl,
			delegateTo:   u.AllowedToDelegateTo,
			rbcdFrom:     ParseRBCDTrustees(u.AllowedToActOnBehalfOfOtherIdentity),
			sidHistory:   u.SIDHistory,
			isGMSA:       u.IsGMSA,
			gmsaTrustees: ParseRBCDTrustees(u.GMSAMembership),
		}

		s.nodes[id] = node
		if u.DN != "" {
			s.dnToID[strings.ToLower(u.DN)] = id
		}
		if u.ObjectSID != "" && id != u.ObjectSID {
			s.sidToID[u.ObjectSID] = id
		}
	}
}

// addGroupNodes creates graph nodes for all security groups.
// Groups are checked for privileged SID suffixes (Domain Admins, Schema Admins, etc.)
// and adminCount=1 to determine if they should be marked as privileged targets.
func (s *AttackGraphService) addGroupNodes(groups []types.Group) {
	for i := range groups {
		g := &groups[i]
		id := g.ObjectSID
		if id == "" {
			id = s.generateID(g.DN)
		}

		isPrivileged := s.isPrivilegedBySID(g.ObjectSID)

		node := &internalNode{
			id:           id,
			dn:           g.DN,
			name:         g.SAMAccountName,
			nodeType:     types.AttackNodeGroup,
			sid:          g.ObjectSID,
			isEnabled:    true,
			isPrivileged: isPrivileged || g.AdminCount,
			adminCount:   g.AdminCount,
			memberOf:     g.MemberOf,
		}

		s.nodes[id] = node
		if g.DN != "" {
			s.dnToID[strings.ToLower(g.DN)] = id
		}
		if g.ObjectSID != "" && id != g.ObjectSID {
			s.sidToID[g.ObjectSID] = id
		}
	}
}

// addComputerNodes creates graph nodes for all computer accounts.
// Computers are checked for Domain Controller status by inspecting memberOf for "Domain Controllers" group.
// Domain Controllers are automatically marked as privileged targets since compromising a DC means full domain compromise.
func (s *AttackGraphService) addComputerNodes(computers []types.Computer) {
	for i := range computers {
		c := &computers[i]
		id := c.ObjectSID
		if id == "" {
			id = s.generateID(c.DN)
		}

		// Check if DC by memberOf containing "Domain Controllers"
		isDC := false
		for _, m := range c.MemberOf {
			if strings.Contains(strings.ToLower(m), "domain controllers") {
				isDC = true
				break
			}
		}
		if isDC {
			s.dcNodeIDs = append(s.dcNodeIDs, id)
		}

		node := &internalNode{
			id:           id,
			dn:           c.DN,
			name:         c.SAMAccountName,
			nodeType:     types.AttackNodeComputer,
			sid:          c.ObjectSID,
			isEnabled:    !c.Disabled,
			isPrivileged: isDC || c.AdminCount,
			adminCount:   c.AdminCount,
			memberOf:     c.MemberOf,
			spn:          c.ServicePrincipalNames,
			uac:          c.UserAccountControl,
			delegateTo:   c.AllowedToDelegateTo,
			rbcdFrom:     ParseRBCDTrustees(c.AllowedToActOnBehalfOfOtherIdentity),
			hasLAPS:      c.HasLegacyLAPS || c.HasWindowsLAPS,
		}

		s.nodes[id] = node
		if c.DN != "" {
			s.dnToID[strings.ToLower(c.DN)] = id
		}
		if c.ObjectSID != "" && id != c.ObjectSID {
			s.sidToID[c.ObjectSID] = id
		}
	}
}

// addOUNodes creates graph nodes for Organizational Units.
// OUs are containers that can hold users, groups, computers, and other OUs.
// Controlling an OU (via ACL abuse) gives control over all contained objects.
// OUs are also GPO link targets: a GPO linked to an OU applies to its contents.
func (s *AttackGraphService) addOUNodes(ous []types.OU) {
	for i := range ous {
		ou := &ous[i]
		if ou.DN == "" {
			continue
		}
		id := s.generateID(ou.DN)

		s.nodes[id] = &internalNode{
			id:        id,
			dn:        ou.DN,
			name:      ou.Name,
			nodeType:  types.AttackNodeOU,
			isEnabled: true,
		}
		s.dnToID[strings.ToLower(ou.DN)] = id
	}
}

// addGPONodes creates graph nodes for Group Policy Objects.
// GPOs linked to OUs can push configuration and scripts to contained objects.
// Controlling a GPO (via ACL abuse) enables code execution on all linked computers.
func (s *AttackGraphService) addGPONodes(gpos []types.GPO) {
	for i := range gpos {
		gpo := &gpos[i]
		if gpo.DN == "" {
			continue
		}
		id := s.generateID(gpo.DN)

		name := gpo.DisplayName
		if name == "" {
			name = gpo.Name
		}

		s.nodes[id] = &internalNode{
			id:        id,
			dn:        gpo.DN,
			name:      name,
			nodeType:  types.AttackNodeGPO,
			isEnabled: gpo.Enabled,
		}
		s.dnToID[strings.ToLower(gpo.DN)] = id

		// Index by CN (GUID) for GPOLink resolution
		cn := gpo.CN
		if cn == "" {
			cn = gpo.GUID
		}
		if cn != "" {
			s.gpoCNToID[strings.ToLower(cn)] = id
		}
	}
}

// --- Edge building ---

// addMembershipEdges creates edges for group membership relationships.
// Each memberOf attribute creates a directed edge from the member to the group.
// These are not marked as abusable since they represent legitimate group membership.
func (s *AttackGraphService) addMembershipEdges() {
	for _, id := range s.sortedNodeIDs() {
		node := s.nodes[id]
		for _, groupDN := range node.memberOf {
			targetID, ok := s.dnToID[strings.ToLower(groupDN)]
			if !ok {
				continue
			}
			s.addEdge(internalEdge{
				source:     node.id,
				target:     targetID,
				relation:   types.RelMemberOf,
				isAbusable: false,
			})
		}
	}
}

// addACLEdges creates edges for dangerous ACL permissions that can be abused for privilege escalation.
// Processes all ALLOWED ACEs and maps access masks to abuse primitives:
//   - GenericAll (full control) → can modify any attribute, reset password, add to groups
//   - WriteDACL → can grant self GenericAll
//   - WriteOwner → can take ownership then grant self permissions
//   - GenericWrite → can modify attributes (e.g., scriptPath, msDS-AllowedToActOnBehalfOfOtherIdentity)
//   - CONTROL_ACCESS + specific GUID → extended rights (DCSync, ForceChangePassword)
//   - Self + Self-Membership GUID → add self to group
//
// Self-referencing ACLs are skipped since they don't enable privilege escalation.
func (s *AttackGraphService) addACLEdges(aclEntries []types.ACLEntry) {
	for _, acl := range aclEntries {
		// Skip non-allow ACEs
		if !strings.Contains(acl.AceType, "ALLOWED") {
			continue
		}

		// Resolve trustee SID to node ID
		trusteeID := acl.Trustee
		if _, ok := s.nodes[trusteeID]; !ok {
			// Try secondary SID index (nodes keyed by DN instead of SID)
			if mappedID, ok2 := s.sidToID[trusteeID]; ok2 {
				trusteeID = mappedID
			} else {
				continue // trustee not in our graph
			}
		}

		// Resolve object DN to node ID
		targetID, ok := s.dnToID[strings.ToLower(acl.ObjectDN)]
		if !ok {
			continue
		}

		// Skip self-referencing ACLs
		if trusteeID == targetID {
			continue
		}

		// Classify ACL relation
		rel, abusable := s.classifyACL(acl.AccessMask, acl.ObjectType)
		if rel == "" {
			continue
		}

		s.addEdge(internalEdge{
			source:     trusteeID,
			target:     targetID,
			relation:   rel,
			accessMask: acl.AccessMask,
			objectType: acl.ObjectType,
			isAbusable: abusable,
		})
	}
}

// classifyACL maps an ACL access mask and objectType GUID to a relation type and abusability flag.
//
// Access Mask Hierarchy (checked in priority order):
//  1. GenericAll (0x10000000) - Full control, highest privilege
//  2. WriteDACL (0x00040000) - Can modify ACL to grant self GenericAll
//  3. WriteOwner (0x00080000) - Can take ownership, then modify ACL
//  4. GenericWrite (0x40000000) - Can write most attributes
//  5. CONTROL_ACCESS (0x00000100) + GUID - Extended rights (DCSync, ForceChangePassword)
//  6. Self (0x00000008) + Self-Membership GUID - Add self to group
//
// Extended Rights GUIDs:
//   - DS-Replication-Get-Changes (1131f6aa-...) + DS-Replication-Get-Changes-All (1131f6ad-...) = DCSync
//   - User-Force-Change-Password (00299570-...) = reset password without knowing current
//   - Self-Membership (bf9679c0-...) with Self mask = add self to group
//
// Returns:
//   - relation: The attack relation type (RelGenericAll, RelDCSync, etc.) or empty string if not abusable
//   - abusable: true if this permission can be exploited for privilege escalation
func (s *AttackGraphService) classifyACL(mask int, objectType string) (types.AttackRelationType, bool) {
	objectType = strings.ToLower(objectType)

	// GenericAll = full control
	if mask&types.MaskGenericAll != 0 {
		return types.RelGenericAll, true
	}

	// WriteDACL
	if mask&types.MaskWriteDACL != 0 {
		return types.RelWriteDacl, true
	}

	// WriteOwner
	if mask&types.MaskWriteOwner != 0 {
		return types.RelWriteOwner, true
	}

	// GenericWrite
	if mask&types.MaskGenericWrite != 0 {
		return types.RelGenericWrite, true
	}

	// Extended rights (CONTROL_ACCESS)
	if mask&types.MaskControlAccess != 0 {
		switch objectType {
		case strings.ToLower(types.GUIDForceChangePassword):
			return types.RelForceChangePassword, true
		case strings.ToLower(types.GUIDDSReplicationGetChanges):
			return types.RelDCSync, true
		case strings.ToLower(types.GUIDDSReplicationGetChangesAll):
			return types.RelDCSync, true
		case strings.ToLower(types.GUIDLAPSPassword):
			return types.RelReadLAPSPassword, true
		case strings.ToLower(types.GUIDCertificateEnrollment):
			return types.RelEnroll, true
		}
	}

	// WriteProperty on specific attributes
	if mask&types.MaskWriteProperty != 0 {
		switch objectType {
		case strings.ToLower(types.GUIDKeyCredentialLink):
			return types.RelWriteKeyCredentialLink, true
		}
	}

	// Self + Self-Membership GUID = AddMember
	if mask&types.MaskSelf != 0 && objectType == strings.ToLower(types.GUIDSelfMembership) {
		return types.RelAddMember, true
	}

	return "", false
}

// addOwnershipEdges creates Owns edges from object owners to owned objects.
// In Active Directory, the Owner SID in an object's security descriptor identifies who
// owns the object. The owner can always modify the DACL (grant self GenericAll),
// making ownership equivalent to full control. This is a privilege escalation vector
// when a non-privileged principal owns a privileged object.
//
// Expected owners (filtered out as non-abusable):
//   - Domain Admins, Enterprise Admins (expected to own everything)
//   - SYSTEM (S-1-5-18), BUILTIN\Administrators (S-1-5-32-544)
//   - The object itself (self-ownership)
func (s *AttackGraphService) addOwnershipEdges(objectOwners map[string]string) {
	if len(objectOwners) == 0 {
		return
	}

	// SIDs that are expected to own objects (not abusable)
	expectedOwners := map[string]bool{
		"S-1-5-18":     true, // SYSTEM
		"S-1-5-32-544": true, // BUILTIN\Administrators
		"S-1-3-0":      true, // Creator Owner
	}
	// Also add domain-specific privileged groups
	if s.domainSID != "" {
		expectedOwners[s.domainSID+"-512"] = true // Domain Admins
		expectedOwners[s.domainSID+"-519"] = true // Enterprise Admins
		expectedOwners[s.domainSID+"-518"] = true // Schema Admins
	}

	for objectDN, ownerSID := range objectOwners {
		if ownerSID == "" {
			continue
		}

		// Skip expected owners (not abusable)
		if expectedOwners[ownerSID] {
			continue
		}

		// Resolve owner SID to node ID
		ownerID := ownerSID
		if _, ok := s.nodes[ownerID]; !ok {
			if mappedID, ok2 := s.sidToID[ownerID]; ok2 {
				ownerID = mappedID
			} else {
				continue // owner not in our graph
			}
		}

		// Resolve object DN to node ID
		targetID, ok := s.dnToID[strings.ToLower(objectDN)]
		if !ok {
			continue
		}

		// Skip self-ownership
		if ownerID == targetID {
			continue
		}

		s.addEdge(internalEdge{
			source:     ownerID,
			target:     targetID,
			relation:   types.RelOwns,
			isAbusable: true,
		})
	}
}

// addDelegationEdges creates edges for Kerberos delegation relationships.
// Constrained delegation (msDS-AllowedToDelegateTo attribute) allows a service to impersonate
// any user when authenticating to specific target services (SPNs).
// This enables privilege escalation if the service can delegate to a privileged target (e.g., DC).
func (s *AttackGraphService) addDelegationEdges() {
	for _, id := range s.sortedNodeIDs() {
		node := s.nodes[id]
		// Constrained delegation
		if len(node.delegateTo) > 0 {
			for _, spnTarget := range node.delegateTo {
				// Resolve SPN to target computer: extract hostname from SPN (format: service/host)
				targetID := s.resolveSPNToNode(spnTarget)
				if targetID == "" {
					continue
				}
				s.addEdge(internalEdge{
					source:     node.id,
					target:     targetID,
					relation:   types.RelAllowedToDelegate,
					isAbusable: true,
				})
			}
		}

		// Unconstrained delegation → edges to all DCs
		// Accounts trusted for delegation can impersonate any user authenticating to them,
		// including Domain Controllers via TGT forwarding. Skip DCs themselves (already privileged).
		if node.uac&types.UACTrustedForDelegation != 0 && !node.isPrivileged {
			for _, dcID := range s.dcNodeIDs {
				s.addEdge(internalEdge{
					source:     node.id,
					target:     dcID,
					relation:   types.RelAllowedToDelegate,
					isAbusable: true,
				})
			}
		}

		// RBCD: Resource-Based Constrained Delegation
		// If a principal is listed in msDS-AllowedToActOnBehalfOfOtherIdentity,
		// they can impersonate any user to authenticate to that resource.
		for _, trusteeSID := range node.rbcdFrom {
			if _, ok := s.nodes[trusteeSID]; !ok {
				continue
			}
			s.addEdge(internalEdge{
				source:     trusteeSID,
				target:     node.id,
				relation:   types.RelAllowedToAct,
				isAbusable: true,
			})
		}
	}
}

// addContainsEdges creates edges from OUs (and the domain root) to their direct child objects.
// This models the AD containment hierarchy: OU → child object.
// Controlling an OU gives control over all contained objects (via inheritance or GPO application).
// An object is "directly contained" if its parent DN (everything after first comma) matches the OU/domain DN.
func (s *AttackGraphService) addContainsEdges() {
	// Build set of container DNs (OUs + domain root)
	containerIDs := make(map[string]string) // lowercase parent DN -> container node ID
	for _, id := range s.sortedNodeIDs() {
		node := s.nodes[id]
		if node.nodeType == types.AttackNodeOU || node.nodeType == types.AttackNodeDomain {
			containerIDs[strings.ToLower(node.dn)] = node.id
		}
	}
	if len(containerIDs) == 0 {
		return
	}

	// For each non-container node, check if its parent DN is a known container
	for _, id := range s.sortedNodeIDs() {
		node := s.nodes[id]
		if node.dn == "" {
			continue
		}
		// Skip containers themselves (OU→OU containment is handled too)
		parentDN := directParentDN(node.dn)
		if parentDN == "" {
			continue
		}

		containerID, ok := containerIDs[strings.ToLower(parentDN)]
		if !ok {
			continue
		}
		// Skip self-reference
		if containerID == node.id {
			continue
		}

		s.addEdge(internalEdge{
			source:     containerID,
			target:     node.id,
			relation:   types.RelContains,
			isAbusable: false,
		})
	}
}

// addGPLinkEdges creates edges from GPOs to the OUs they are linked to.
// A GPO linked to an OU applies its policies to all objects in that OU.
// This enables attack paths: Attacker → (ACL abuse) → GPO → (GPLink) → OU → (Contains) → target.
func (s *AttackGraphService) addGPLinkEdges(gpoLinks []GPOLink) {
	for _, link := range gpoLinks {
		if !link.LinkEnabled {
			continue
		}

		// Resolve GPO CN to node ID
		gpoCN := strings.ToLower(link.GPOCN)
		if gpoCN == "" {
			gpoCN = strings.ToLower(link.GPOGuid)
		}
		gpoID, ok := s.gpoCNToID[gpoCN]
		if !ok {
			continue
		}

		// Resolve linked OU/site DN to node ID
		targetID, ok := s.dnToID[strings.ToLower(link.LinkedTo)]
		if !ok {
			continue
		}

		s.addEdge(internalEdge{
			source:     gpoID,
			target:     targetID,
			relation:   types.RelGPLink,
			isAbusable: false,
		})
	}
}

// addGPOACLEdges creates edges for dangerous ACL permissions on GPOs.
// GPO ACLs are collected separately from regular ACLs (via GetGPOAcls).
// Only GenericAll/WriteDACL/WriteOwner/GenericWrite are relevant for GPO abuse
// since modifying a GPO enables code execution on linked computers.
func (s *AttackGraphService) addGPOACLEdges(gpoAcls []GPOAcl) {
	for _, acl := range gpoAcls {
		if !strings.Contains(acl.AceType, "ALLOWED") {
			continue
		}

		// Resolve trustee SID to node ID
		trusteeID := acl.TrusteeSID
		if trusteeID == "" {
			continue
		}
		if _, ok := s.nodes[trusteeID]; !ok {
			if mappedID, ok2 := s.sidToID[trusteeID]; ok2 {
				trusteeID = mappedID
			} else {
				continue
			}
		}

		// Resolve GPO DN to node ID
		targetID, ok := s.dnToID[strings.ToLower(acl.GPODN)]
		if !ok {
			continue
		}

		// Skip self-referencing ACLs
		if trusteeID == targetID {
			continue
		}

		// Classify: only generic dangerous permissions matter for GPO abuse
		rel, abusable := s.classifyACL(acl.AccessMask, "")
		if rel == "" {
			continue
		}

		s.addEdge(internalEdge{
			source:     trusteeID,
			target:     targetID,
			relation:   rel,
			accessMask: acl.AccessMask,
			isAbusable: abusable,
		})
	}
}

// addSIDHistoryEdges creates HasSIDHistory edges for users/computers whose sIDHistory
// contains the SID of another principal. SID history is an identity equivalence: if user A
// has the SID of group B in its sIDHistory, A effectively IS B for access control purposes.
func (s *AttackGraphService) addSIDHistoryEdges() {
	for _, id := range s.sortedNodeIDs() {
		node := s.nodes[id]
		if len(node.sidHistory) == 0 {
			continue
		}
		for _, historySID := range node.sidHistory {
			targetID := historySID
			if mapped, ok := s.sidToID[historySID]; ok {
				targetID = mapped
			}
			if _, exists := s.nodes[targetID]; !exists {
				continue
			}
			if targetID == node.id {
				continue
			}
			s.addEdge(internalEdge{
				source:     node.id,
				target:     targetID,
				relation:   types.RelHasSIDHistory,
				isAbusable: true,
			})
		}
	}
}

// addGMSAEdges creates ReadGMSAPassword edges from trustees listed in the gMSA's
// msDS-GroupMSAMembership security descriptor. This is the same binary SD format as RBCD.
func (s *AttackGraphService) addGMSAEdges() {
	for _, id := range s.sortedNodeIDs() {
		node := s.nodes[id]
		if !node.isGMSA || len(node.gmsaTrustees) == 0 {
			continue
		}
		for _, trusteeSID := range node.gmsaTrustees {
			sourceID := trusteeSID
			if mapped, ok := s.sidToID[trusteeSID]; ok {
				sourceID = mapped
			}
			if _, exists := s.nodes[sourceID]; !exists {
				continue
			}
			if sourceID == node.id {
				continue
			}
			// Edge: trustee → gMSA (trustee can read the gMSA password)
			s.addEdge(internalEdge{
				source:     sourceID,
				target:     node.id,
				relation:   types.RelReadGMSAPassword,
				isAbusable: true,
			})
		}
	}
}

// addCertTemplateNodes creates graph nodes for certificate templates.
// Templates vulnerable to ESC1 (enrollee supplies subject + auth EKU + no approval) are marked.
func (s *AttackGraphService) addCertTemplateNodes(templates []types.CertTemplate) {
	for i := range templates {
		t := &templates[i]
		id := s.generateID(t.DN)

		isESC1 := (t.SubjectNameFlag&0x01) != 0 && // CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT
			hasAuthenticationEKU(t.ExtendedKeyUsage) &&
			!t.RequiresManagerApproval

		node := &internalNode{
			id:                       id,
			dn:                       t.DN,
			name:                     t.Name,
			nodeType:                 types.AttackNodeCertTemplate,
			isEnabled:                true,
			isVulnerableCertTemplate: isESC1,
		}

		s.nodes[id] = node
		if t.DN != "" {
			s.dnToID[strings.ToLower(t.DN)] = id
		}
	}
}

// addCertAbuseEdges creates edges from ESC1-vulnerable cert templates to the domain node.
// If a template allows enrollee-supplied subjects with auth EKU, an attacker with enrollment
// rights can impersonate any domain user, effectively compromising the domain.
func (s *AttackGraphService) addCertAbuseEdges() {
	// Find domain node
	var domainNodeID string
	for _, id := range s.sortedNodeIDs() {
		if s.nodes[id].nodeType == types.AttackNodeDomain {
			domainNodeID = id
			break
		}
	}
	if domainNodeID == "" {
		return
	}

	for _, id := range s.sortedNodeIDs() {
		node := s.nodes[id]
		if node.nodeType != types.AttackNodeCertTemplate || !node.isVulnerableCertTemplate {
			continue
		}
		// Template → Domain (represents "can impersonate any user")
		s.addEdge(internalEdge{
			source:     node.id,
			target:     domainNodeID,
			relation:   types.RelGenericAll,
			isAbusable: true,
		})
	}
}

// hasAuthenticationEKU checks if EKU list allows authentication (Client Auth, Smart Card, PKINIT, or empty=Any Purpose).
func hasAuthenticationEKU(ekus []string) bool {
	if len(ekus) == 0 {
		return true // Empty EKU = Any Purpose
	}
	for _, eku := range ekus {
		switch eku {
		case "1.3.6.1.5.5.7.3.2", // Client Authentication
			"1.3.6.1.4.1.311.20.2.2", // Smart Card Logon
			"1.3.6.1.5.2.3.4",        // PKINIT Client Authentication
			"2.5.29.37.0":            // Any Purpose
			return true
		}
	}
	return false
}

// resolveSPNToNode extracts the hostname from an SPN and finds the corresponding computer node.
// SPN format: service/hostname[:port] (e.g., "cifs/DC01.domain.com" or "HTTP/webserver:8080")
// Matches computer SAMAccountName (without trailing $) or FQDN prefix.
func (s *AttackGraphService) resolveSPNToNode(spn string) string {
	// Extract hostname from SPN (e.g., "cifs/DC01.domain.com" -> "DC01")
	parts := strings.SplitN(spn, "/", 2)
	if len(parts) < 2 {
		return ""
	}
	hostname := strings.ToLower(parts[1])
	// Remove port if present
	if idx := strings.IndexByte(hostname, ':'); idx >= 0 {
		hostname = hostname[:idx]
	}

	// Try to find a computer node by matching SAMAccountName or hostname
	for _, id := range s.sortedNodeIDs() {
		node := s.nodes[id]
		if node.nodeType != types.AttackNodeComputer {
			continue
		}
		nodeName := strings.ToLower(strings.TrimSuffix(node.name, "$"))
		if hostname == nodeName || strings.HasPrefix(hostname, nodeName+".") {
			return node.id
		}
	}
	return ""
}

// --- Target identification ---

// identifyPrivilegedTargets marks nodes as privileged based on multiple criteria:
//
// 1. Well-Known SID Suffixes (highest priority):
//   - Domain Admins (-512), Enterprise Admins (-519), Schema Admins (-518)
//   - Domain Controllers (-516), Cert Publishers (-517), etc.
//   - See types.PrivilegedSIDSuffixes for complete list
//
// 2. adminCount=1 (SDProp protection):
//   - Indicates current or past membership in protected admin groups
//   - SDProp process sets this flag on objects in privileged groups
//   - Applies to users, groups, and computers
//
// 3. Domain Controller computers:
//   - Identified by membership in "Domain Controllers" group
//   - DCs are always privileged since they hold domain secrets (NTDS.dit, Kerberos keys)
//
// 4. Name-based detection (fallback for edge cases):
//   - Multilingual support: "Domain Admins", "Admins du domaine", "Administrators", "Administrateurs"
//   - Catches privileged groups even if SID is missing or non-standard
//
// Nodes marked as privileged become BFS target candidates. Any path reaching these nodes
// represents a privilege escalation opportunity.
func (s *AttackGraphService) identifyPrivilegedTargets() {
	for _, id := range s.sortedNodeIDs() {
		node := s.nodes[id]
		// Check SID suffix
		if reason, ok := s.checkPrivilegedSID(node.sid); ok {
			node.isPrivileged = true
			s.privilegedTargets[node.id] = types.AttackTarget{
				ID:     node.id,
				Name:   node.name,
				Type:   node.nodeType,
				SID:    node.sid,
				DN:     node.dn,
				Reason: reason,
			}
			continue
		}

		// Check adminCount (applies to all node types: users, groups, computers)
		if node.adminCount {
			node.isPrivileged = true
			if _, exists := s.privilegedTargets[node.id]; !exists {
				s.privilegedTargets[node.id] = types.AttackTarget{
					ID:     node.id,
					Name:   node.name,
					Type:   node.nodeType,
					SID:    node.sid,
					DN:     node.dn,
					Reason: "adminCount=1",
				}
			}
		}

		// Check Domain Controller computers (marked isPrivileged during node creation)
		if node.nodeType == types.AttackNodeComputer && node.isPrivileged {
			if _, exists := s.privilegedTargets[node.id]; !exists {
				s.privilegedTargets[node.id] = types.AttackTarget{
					ID:     node.id,
					Name:   node.name,
					Type:   node.nodeType,
					SID:    node.sid,
					DN:     node.dn,
					Reason: "Domain Controller",
				}
			}
		}

		// Check name-based detection for Domain Admins (multilingual)
		if node.nodeType == types.AttackNodeGroup {
			nameLower := strings.ToLower(node.name)
			if nameLower == "domain admins" || nameLower == "admins du domaine" ||
				nameLower == "enterprise admins" || nameLower == "schema admins" ||
				nameLower == "administrators" || nameLower == "administrateurs" {
				node.isPrivileged = true
				if _, exists := s.privilegedTargets[node.id]; !exists {
					s.privilegedTargets[node.id] = types.AttackTarget{
						ID:     node.id,
						Name:   node.name,
						Type:   node.nodeType,
						SID:    node.sid,
						DN:     node.dn,
						Reason: node.name,
					}
				}
			}
		}
	}
}

// checkPrivilegedSID checks if a SID matches a well-known privileged SID suffix.
// Domain SID format: S-1-5-21-<domain-id>-<RID>
// Privileged RIDs: 512 (Domain Admins), 519 (Enterprise Admins), 518 (Schema Admins), etc.
// Returns the group name and true if privileged, empty string and false otherwise.
func (s *AttackGraphService) checkPrivilegedSID(sid string) (string, bool) {
	if sid == "" {
		return "", false
	}
	for suffix, name := range types.PrivilegedSIDSuffixes {
		if strings.HasSuffix(sid, suffix) {
			return name, true
		}
	}
	return "", false
}

// --- BFS path finding ---

// findAllAttackPaths runs BFS from all non-privileged nodes to find privilege escalation paths.
//
// Algorithm:
//  1. Build set of privileged target node IDs
//  2. For each non-privileged, enabled source node:
//     - Run BFS to find shortest path to any privileged target
//     - Build AttackPath with metadata (risk, type, description, mitigation)
//     - Stop when maxPaths limit reached
//  3. Sort results by risk (critical first) then by hop count (shortest first)
//
// Source node selection:
//   - Skip privileged nodes (already privileged, no escalation needed)
//   - Skip disabled user accounts (cannot authenticate, no attack surface)
//   - Include groups and computers even if disabled (can still have memberships/ACLs)
//
// Performance:
//   - Complexity: O(N * (V + E)) where N=non-privileged nodes, V=all nodes, E=edges
//   - Typical domain: N≈10,000 users, V≈15,000 objects, E≈50,000 relationships
//   - maxPaths limit prevents excessive memory (500 paths = ~5MB typical)
//
// Returns selected attack paths sorted by risk and hop count, plus total candidate count.
func (s *AttackGraphService) findAllAttackPaths(maxPaths int) ([]types.AttackPath, int, map[types.AttackPathType]int) {
	if len(s.privilegedTargets) == 0 {
		return nil, 0, nil
	}

	// Build target ID set
	targetIDs := make(map[string]bool, len(s.privilegedTargets))
	for id := range s.privilegedTargets {
		targetIDs[id] = true
	}

	// Collect candidates with a soft cap to prevent unbounded growth
	collectCap := maxPaths * 3
	var candidates []types.AttackPath
	pathIdx := 0

	// For each non-privileged source node (users, groups, computers).
	// selectPaths below applies per-type/per-target caps on TIES (same risk,
	// same hop count) — a randomized visit order wouldn't just reorder the
	// output, it would change WHICH candidates survive the cap. sortedNodeIDs
	// keeps this deterministic; see its doc comment.
	// Only skip disabled users (groups/computers are always valid sources)
	for _, id := range s.sortedNodeIDs() {
		node := s.nodes[id]
		if node.isPrivileged {
			continue
		}
		if node.nodeType == types.AttackNodeUser && !node.isEnabled {
			continue
		}

		path := s.bfsShortestPath(node.id, targetIDs)
		if path == nil {
			continue
		}

		attackPath := s.buildAttackPath(path, node, pathIdx)
		if attackPath != nil {
			candidates = append(candidates, *attackPath)
			pathIdx++
		}

		if len(candidates) >= collectCap {
			break
		}
	}

	totalCandidates := len(candidates)

	// Count candidates by type before selection (for SaaS stats)
	candidatesByType := make(map[types.AttackPathType]int)
	for i := range candidates {
		candidatesByType[candidates[i].Type]++
	}

	// Sort by risk (critical first), then by hops (shortest first)
	sort.Slice(candidates, func(i, j int) bool {
		ri := riskOrder(candidates[i].Risk)
		rj := riskOrder(candidates[j].Risk)
		if ri != rj {
			return ri < rj
		}
		return candidates[i].Hops < candidates[j].Hops
	})

	// Apply smart selection: per-type caps + per-target diversity
	selected := s.selectPaths(candidates, maxPaths)

	return selected, totalCandidates, candidatesByType
}

// selectPaths applies per-type caps and per-target diversity limits.
// Candidates must be pre-sorted by risk then hops (critical/short first).
func (s *AttackGraphService) selectPaths(candidates []types.AttackPath, maxPaths int) []types.AttackPath {
	typeCounts := make(map[types.AttackPathType]int)
	targetCounts := make(map[string]int)
	var selected []types.AttackPath

	for i := range candidates {
		if len(selected) >= maxPaths {
			break
		}

		p := &candidates[i]

		// Per-type cap
		cap, ok := pathTypeCaps[p.Type]
		if !ok {
			cap = 30
		}
		if typeCounts[p.Type] >= cap {
			continue
		}

		// Per-target diversity
		if targetCounts[p.Target.ID] >= maxPathsPerTarget {
			continue
		}

		// Re-number the path ID
		p.ID = fmt.Sprintf("path-%03d", len(selected)+1)
		selected = append(selected, *p)
		typeCounts[p.Type]++
		targetCounts[p.Target.ID]++
	}

	return selected
}

// bfsShortestPath implements breadth-first search to find the shortest privilege escalation path
// from a source node to any privileged target node.
//
// Algorithm Details:
//  1. Initialize queue with source node (distance 0)
//  2. Mark source as visited to prevent cycles
//  3. While queue not empty:
//     a. Dequeue current node and its path
//     b. Check if current node is a privileged target (path found!)
//     c. If path length > 6 hops, skip exploration (performance limit)
//     d. For each outgoing edge from current node:
//     - Skip if target already visited (prevents cycles)
//     - Mark target as visited
//     - Create new path with target appended
//     - If target is privileged, return immediately (shortest path guarantee)
//     - Otherwise, enqueue target for further exploration
//  4. Return nil if no path found
//
// BFS Properties:
//   - Guarantees shortest path (minimum hops) due to level-order traversal
//   - Early termination: returns immediately on first privileged target hit (line 542)
//   - Visited set prevents infinite loops from circular group memberships
//
// 6-Hop Limit Rationale:
//   - BloodHound uses 6-hop maximum (industry standard)
//   - Prevents exponential explosion on highly-connected graphs
//   - Paths >6 hops are typically impractical for real attacks
//   - Example: User → Group1 → Group2 → Group3 → ACL → TargetGroup → Domain Admins (6 hops)
//
// Complexity:
//   - Time: O(V + E) typical BFS, where V=nodes, E=edges
//   - Space: O(V) for visited set + queue
//   - Worst case: explores entire graph if no path exists
//
// Returns:
//   - bfsPath with node sequence and edges if path found
//   - nil if no path exists or all paths exceed 6 hops
func (s *AttackGraphService) bfsShortestPath(sourceID string, targetIDs map[string]bool) *bfsPath {
	type queueItem struct {
		nodeID string
		path   bfsPath
	}

	visited := map[string]bool{sourceID: true}
	queue := []queueItem{{
		nodeID: sourceID,
		path:   bfsPath{nodes: []string{sourceID}},
	}}

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]

		// Check if we reached a target
		if targetIDs[current.nodeID] && len(current.path.nodes) > 1 {
			return &current.path
		}

		// Max 6 hops
		if len(current.path.nodes) > 6 {
			continue
		}

		// Explore outgoing edges
		outEdges := s.edges[current.nodeID]
		for _, edge := range outEdges {
			if visited[edge.target] {
				continue
			}
			visited[edge.target] = true

			newPath := bfsPath{
				nodes: make([]string, len(current.path.nodes)+1),
				edges: make([]internalEdge, len(current.path.edges)+1),
			}
			copy(newPath.nodes, current.path.nodes)
			newPath.nodes[len(current.path.nodes)] = edge.target
			copy(newPath.edges, current.path.edges)
			newPath.edges[len(current.path.edges)] = edge

			// Prioritize: if this target is privileged, return immediately
			if targetIDs[edge.target] {
				return &newPath
			}

			queue = append(queue, queueItem{nodeID: edge.target, path: newPath})
		}
	}

	return nil
}

// --- Path building ---

func (s *AttackGraphService) buildAttackPath(path *bfsPath, source *internalNode, idx int) *types.AttackPath {
	if len(path.nodes) < 2 {
		return nil
	}

	pathType := s.classifyPathType(path, source)
	risk := s.calculatePathRisk(path, pathType)

	// Build chain (alternating node/relation)
	chain := make([]interface{}, 0, len(path.nodes)+len(path.edges))
	for i, nodeID := range path.nodes {
		n := s.nodes[nodeID]
		if n == nil {
			continue
		}
		chain = append(chain, types.AttackGraphNode{
			ID:           n.id,
			Name:         n.name,
			Type:         n.nodeType,
			SID:          n.sid,
			IsEnabled:    n.isEnabled,
			IsPrivileged: n.isPrivileged,
		})
		if i < len(path.edges) {
			e := path.edges[i]
			var maskPtr *int
			if e.accessMask != 0 {
				maskPtr = &e.accessMask
			}
			chain = append(chain, types.AttackGraphRelation{
				Relation:   e.relation,
				IsAbusable: e.isAbusable,
				AccessMask: maskPtr,
				ObjectType: e.objectType,
			})
		}
	}

	// Get target node
	targetID := path.nodes[len(path.nodes)-1]
	targetNode := s.nodes[targetID]
	if targetNode == nil {
		return nil
	}

	target := types.AttackGraphNode{
		ID:           targetNode.id,
		Name:         targetNode.name,
		Type:         targetNode.nodeType,
		SID:          targetNode.sid,
		IsEnabled:    targetNode.isEnabled,
		IsPrivileged: targetNode.isPrivileged,
	}

	// Build entry point
	entryPoint := types.AttackEntryPoint{
		ID:   source.id,
		Name: source.name,
		Type: source.nodeType,
		Properties: types.AttackEntryPointProperties{
			HasSPN:            len(source.spn) > 0,
			NoPreauth:         source.uac&types.UACDontRequirePreauth != 0,
			PasswordNotExpire: source.uac&types.UACDontExpirePassword != 0,
			Unconstrained:     source.uac&types.UACTrustedForDelegation != 0,
			Constrained:       len(source.delegateTo) > 0,
			RBCD:              len(source.rbcdFrom) > 0,
			AdminCount:        source.adminCount,
			Enabled:           source.isEnabled,
		},
	}

	hops := len(path.nodes) - 1
	description := s.generateDescription(source, targetNode, pathType, hops)
	mitigation := s.generateMitigation(pathType)

	return &types.AttackPath{
		ID:          fmt.Sprintf("path-%03d", idx+1),
		Risk:        risk,
		Type:        pathType,
		Hops:        hops,
		Description: description,
		Chain:       chain,
		EntryPoint:  entryPoint,
		Target:      target,
		Mitigation:  mitigation,
	}
}

// --- Classification ---

// classifyPathType determines the attack type based on path characteristics and source node attributes.
//
// Classification is priority-based (first match wins):
//
// 1. DCSync (Highest Priority):
//   - Any path containing DS-Replication-Get-Changes or DS-Replication-Get-Changes-All extended rights
//   - Allows attacker to replicate domain password hashes (full domain compromise)
//   - Example: User → GenericAll on Domain Object → DCSync
//
// 2. Delegation Abuse:
//   - Path contains AllowedToDelegate (constrained) or AllowedToAct (RBCD) relations
//   - Enables Kerberos ticket forgery to impersonate privileged users
//   - Example: ServiceAccount (delegateTo DC) → Domain Admin
//
// 3. Kerberoasting:
//   - Source user has ServicePrincipalNames (SPNs)
//   - Attacker can request Kerberos TGS and offline crack service account password
//   - Example: User (with SPN) → MemberOf → Privileged Group
//
// 4. AS-REP Roasting:
//   - Source user has UAC flag DONT_REQ_PREAUTH (0x400000)
//   - Attacker can request AS-REP without pre-auth and offline crack password
//   - Example: User (no preauth) → MemberOf → Domain Admins
//
// 5. Ownership Abuse:
//   - Path contains Owns relation
//   - Owner can modify object DACL to grant self full control
//
// 6. ACL Abuse (Default for abusable permissions):
//   - Path contains abusable ACL permissions (GenericAll, WriteDACL, WriteOwner, etc.)
//   - Example: User → WriteDACL on TargetUser → ForceChangePassword → Domain Admin
//
// 7. Group Membership (Baseline):
//   - All edges are MemberOf (pure nested group membership)
//   - Least dangerous but still represents privilege path
//   - Example: User → Group1 → Group2 → Domain Admins
//
// Returns the most dangerous attack type present in the path.
func (s *AttackGraphService) classifyPathType(path *bfsPath, source *internalNode) types.AttackPathType {
	relations := make(map[types.AttackRelationType]bool)
	hasAbusable := false
	allMemberOf := true

	for _, edge := range path.edges {
		relations[edge.relation] = true
		if edge.isAbusable {
			hasAbusable = true
		}
		if edge.relation != types.RelMemberOf {
			allMemberOf = false
		}
	}

	// Priority-based classification (matches TS)
	if relations[types.RelDCSync] {
		return types.PathDCSync
	}
	if relations[types.RelHasSIDHistory] {
		return types.PathSIDHistory
	}
	if relations[types.RelEnroll] {
		return types.PathCertAbuse
	}
	if relations[types.RelReadGMSAPassword] {
		return types.PathGMSAAbuse
	}
	if relations[types.RelReadLAPSPassword] {
		return types.PathLAPSAbuse
	}
	if relations[types.RelAllowedToDelegate] || relations[types.RelAllowedToAct] {
		return types.PathDelegationAbuse
	}
	if len(source.spn) > 0 && source.nodeType == types.AttackNodeUser {
		return types.PathKerberoasting
	}
	if source.uac&types.UACDontRequirePreauth != 0 {
		return types.PathASREPRoasting
	}
	if relations[types.RelOwns] {
		return types.PathOwnershipAbuse
	}
	if hasAbusable {
		return types.PathACLAbuse
	}
	if allMemberOf {
		return types.PathGroupMembership
	}
	return types.PathACLAbuse
}

// calculatePathRisk assigns a risk severity based on path length, attack type, and exploitability.
//
// Risk Tiers (priority order):
//
// Critical:
//  1. DCSync paths (always critical) - direct domain compromise via password replication
//  2. Short abusable paths (≤2 hops with abusable ACL) - quick exploitation, hard to detect
//     Example: User → GenericAll on Admin → Domain Admins (2 hops, immediately exploitable)
//
// High:
//  3. Delegation abuse paths - Kerberos delegation enables impersonation attacks
//  4. Short paths without abusable ACLs (≤2 hops) - quick path but may require additional steps
//     Example: User → MemberOf → Domain Admins (2 hops, legitimate membership)
//
// Medium:
//  5. Medium-length paths (3-4 hops) - requires multiple steps, more detection opportunities
//     Example: User → Group1 → Group2 → AdminGroup → Domain Admins (4 hops)
//
// Low:
//  6. Long paths (5-6 hops) - complex exploitation chain, many detection points, less practical
//
// Rationale:
//   - Shorter paths = faster exploitation = higher risk
//   - Abusable ACLs = technical exploitation possible = higher risk
//   - DCSync = complete domain compromise = always critical
//   - Delegation = powerful Kerberos attacks = high risk
//
// Risk scoring influences prioritization in security reports and remediation planning.
func (s *AttackGraphService) calculatePathRisk(path *bfsPath, pathType types.AttackPathType) types.AttackPathRisk {
	hops := len(path.nodes) - 1

	// DCSync is always critical
	if pathType == types.PathDCSync {
		return types.AttackRiskCritical
	}

	// SID history = always critical (identity equivalence)
	if pathType == types.PathSIDHistory {
		return types.AttackRiskCritical
	}

	// Certificate abuse = always critical (domain compromise via impersonation)
	if pathType == types.PathCertAbuse {
		return types.AttackRiskCritical
	}

	// LAPS/gMSA: critical if short, otherwise high
	if pathType == types.PathLAPSAbuse || pathType == types.PathGMSAAbuse {
		if hops <= 2 {
			return types.AttackRiskCritical
		}
		return types.AttackRiskHigh
	}

	// Short path with abusable edge = critical
	hasAbusable := false
	for _, e := range path.edges {
		if e.isAbusable {
			hasAbusable = true
			break
		}
	}
	if hops <= 2 && hasAbusable {
		return types.AttackRiskCritical
	}

	// Delegation abuse = high
	if pathType == types.PathDelegationAbuse {
		return types.AttackRiskHigh
	}

	// Short path = high
	if hops <= 2 {
		return types.AttackRiskHigh
	}

	// Medium path
	if hops <= 4 {
		return types.AttackRiskMedium
	}

	return types.AttackRiskLow
}

// --- Statistics ---

// computeStats calculates aggregate statistics across all discovered attack paths.
// Provides summary metrics for security posture assessment:
//   - Total paths found (attack surface size)
//   - Distribution by risk level (critical/high/medium/low counts)
//   - Distribution by attack type (Kerberoasting, DCSync, ACL abuse, etc.)
//   - Path length metrics: shortest, longest, average hops
func (s *AttackGraphService) computeStats(paths []types.AttackPath, totalCandidates int, candidatesByType map[types.AttackPathType]int) types.AttackGraphStats {
	stats := types.AttackGraphStats{
		TotalPaths:       len(paths),
		TotalCandidates:  totalCandidates,
		CandidatesByType: candidatesByType,
		ByRisk: map[types.AttackPathRisk]int{
			types.AttackRiskCritical: 0,
			types.AttackRiskHigh:     0,
			types.AttackRiskMedium:   0,
			types.AttackRiskLow:      0,
		},
		ByType:   make(map[types.AttackPathType]int),
		ByTarget: make(map[string]types.AttackTargetStat),
	}

	if len(paths) == 0 {
		return stats
	}

	totalHops := 0
	stats.ShortestPath = paths[0].Hops
	stats.LongestPath = paths[0].Hops

	for _, p := range paths {
		stats.ByRisk[p.Risk]++
		stats.ByType[p.Type]++
		totalHops += p.Hops
		if p.Hops < stats.ShortestPath {
			stats.ShortestPath = p.Hops
		}
		if p.Hops > stats.LongestPath {
			stats.LongestPath = p.Hops
		}

		// Per-target stats
		ts, ok := stats.ByTarget[p.Target.ID]
		if !ok {
			ts = types.AttackTargetStat{
				Name:   p.Target.Name,
				ByType: make(map[types.AttackPathType]int),
			}
		}
		ts.TotalPaths++
		ts.ByType[p.Type]++
		stats.ByTarget[p.Target.ID] = ts
	}

	stats.AverageHops = float64(totalHops) / float64(len(paths))
	return stats
}

// getUniqueNodes extracts all unique nodes appearing in attack paths and counts their path frequency.
// Nodes appearing in many paths are high-value targets for remediation since fixing them
// breaks multiple attack chains.
//
// Example: If GroupA appears in 15 different attack paths, removing unnecessary privileges
// from GroupA or reducing its membership will eliminate 15 escalation vectors.
//
// Returns nodes sorted by path count (descending), enabling prioritized remediation.
func (s *AttackGraphService) getUniqueNodes(paths []types.AttackPath) []types.AttackGraphUniqueNode {
	nodeCounts := make(map[string]int)
	nodeInfos := make(map[string]*internalNode)

	for _, p := range paths {
		seen := make(map[string]bool)
		for _, elem := range p.Chain {
			if gn, ok := elem.(types.AttackGraphNode); ok {
				if !seen[gn.ID] {
					nodeCounts[gn.ID]++
					seen[gn.ID] = true
					if _, exists := nodeInfos[gn.ID]; !exists {
						nodeInfos[gn.ID] = s.nodes[gn.ID]
					}
				}
			}
		}
	}

	result := make([]types.AttackGraphUniqueNode, 0, len(nodeCounts))
	for id, count := range nodeCounts {
		n := nodeInfos[id]
		if n == nil {
			continue
		}
		result = append(result, types.AttackGraphUniqueNode{
			ID:        n.id,
			Name:      n.name,
			Type:      n.nodeType,
			PathCount: count,
			SID:       n.sid,
		})
	}

	// Sort by path count descending, ID ascending to break ties (T_046/B_048):
	// result was built by ranging nodeCounts, a map, so two nodes with the
	// same PathCount landed in a randomized relative order across runs.
	sort.Slice(result, func(i, j int) bool {
		if result[i].PathCount != result[j].PathCount {
			return result[i].PathCount > result[j].PathCount
		}
		return result[i].ID < result[j].ID
	})

	return result
}

// --- Helpers ---

func (s *AttackGraphService) addEdge(e internalEdge) {
	s.edges[e.source] = append(s.edges[e.source], e)
}

// sortedNodeIDs returns every node ID in s.nodes in a fixed, deterministic
// order (T_046/B_048). s.nodes is a map, so `for _, node := range s.nodes`
// visits nodes in a randomized order per process — every edge-building pass
// and the BFS source-node loop used it, so the SAME domain produced a
// different graph (different edge order at a fan-in node, different
// candidate order feeding findAllAttackPaths' per-type/per-target caps)
// on every run of the exact same input. Every s.nodes iteration in this file
// now goes through this helper instead of ranging the map directly.
func (s *AttackGraphService) sortedNodeIDs() []string {
	ids := make([]string, 0, len(s.nodes))
	for id := range s.nodes {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

func (s *AttackGraphService) generateID(dn string) string {
	return "dn:" + strings.ToLower(dn)
}

func (s *AttackGraphService) isPrivilegedBySID(sid string) bool {
	return IsPrivilegedSID(sid)
}

func (s *AttackGraphService) extractDomainSID(users []types.User) string {
	for _, u := range users {
		if u.ObjectSID != "" {
			// Domain SID = everything up to last "-"
			if idx := strings.LastIndex(u.ObjectSID, "-"); idx > 0 {
				return u.ObjectSID[:idx]
			}
		}
	}
	return ""
}

func (s *AttackGraphService) generateDescription(source, target *internalNode, pathType types.AttackPathType, hops int) string {
	switch pathType {
	case types.PathKerberoasting:
		return fmt.Sprintf("%s has an SPN and can be Kerberoasted to reach %s in %d hop(s)", source.name, target.name, hops)
	case types.PathASREPRoasting:
		return fmt.Sprintf("%s does not require Kerberos pre-authentication and can reach %s in %d hop(s)", source.name, target.name, hops)
	case types.PathDCSync:
		return fmt.Sprintf("%s has DCSync rights allowing domain replication to reach %s in %d hop(s)", source.name, target.name, hops)
	case types.PathDelegationAbuse:
		return fmt.Sprintf("%s can abuse delegation to impersonate privileged users reaching %s in %d hop(s)", source.name, target.name, hops)
	case types.PathACLAbuse:
		return fmt.Sprintf("%s can abuse ACL permissions to reach %s in %d hop(s)", source.name, target.name, hops)
	case types.PathGroupMembership:
		return fmt.Sprintf("%s is a member of groups leading to %s in %d hop(s)", source.name, target.name, hops)
	case types.PathOwnershipAbuse:
		return fmt.Sprintf("%s owns objects in the path to %s in %d hop(s)", source.name, target.name, hops)
	case types.PathSIDHistory:
		return fmt.Sprintf("%s has SID history containing the SID of %s, granting equivalent identity in %d hop(s)", source.name, target.name, hops)
	case types.PathLAPSAbuse:
		return fmt.Sprintf("%s can read the LAPS password of %s in %d hop(s)", source.name, target.name, hops)
	case types.PathGMSAAbuse:
		return fmt.Sprintf("%s can read the gMSA password of %s in %d hop(s)", source.name, target.name, hops)
	case types.PathCertAbuse:
		return fmt.Sprintf("%s can abuse certificate enrollment to impersonate any domain user via %s in %d hop(s)", source.name, target.name, hops)
	default:
		return fmt.Sprintf("%s can reach %s in %d hop(s) via %s", source.name, target.name, hops, string(pathType))
	}
}

func (s *AttackGraphService) generateMitigation(pathType types.AttackPathType) string {
	switch pathType {
	case types.PathKerberoasting:
		return "Remove unnecessary SPNs from user accounts. Use Group Managed Service Accounts (gMSA) or strong passwords for service accounts."
	case types.PathASREPRoasting:
		return "Enable Kerberos pre-authentication for all accounts. Use strong, unique passwords."
	case types.PathDCSync:
		return "Remove unnecessary replication rights. Only Domain Controllers should have DCSync permissions."
	case types.PathDelegationAbuse:
		return "Remove unnecessary delegation configurations. Use constrained delegation with protocol transition restrictions."
	case types.PathACLAbuse:
		return "Review and remove excessive ACL permissions. Follow the principle of least privilege."
	case types.PathGroupMembership:
		return "Review group membership chains. Remove unnecessary nested group memberships to reduce attack surface."
	case types.PathOwnershipAbuse:
		return "Review object ownership. Ensure only authorized administrators own sensitive objects."
	case types.PathCertAbuse:
		return "Review certificate template permissions and configurations. Remove overly permissive enrollment rights. Disable enrollee-supplied subject names where not required."
	case types.PathSIDHistory:
		return "Remove SID history entries using 'netdom trust /cleanSIDHistory'. SID history should only exist temporarily during domain migrations."
	case types.PathLAPSAbuse:
		return "Restrict LAPS password read permissions to authorized administrators only. Review and clean up ControlAccess ACEs on computer objects."
	case types.PathGMSAAbuse:
		return "Review msDS-GroupMSAMembership on gMSA accounts. Restrict password read access to only the service accounts that need it."
	default:
		return "Review and remediate the identified attack path to reduce privilege escalation risk."
	}
}

// directParentDN returns the parent DN of an object (everything after the first comma).
// For example: "CN=john,OU=IT,DC=corp,DC=com" → "OU=IT,DC=corp,DC=com"
func directParentDN(dn string) string {
	idx := strings.Index(dn, ",")
	if idx < 0 || idx >= len(dn)-1 {
		return ""
	}
	return dn[idx+1:]
}

func riskOrder(risk types.AttackPathRisk) int {
	switch risk {
	case types.AttackRiskCritical:
		return 0
	case types.AttackRiskHigh:
		return 1
	case types.AttackRiskMedium:
		return 2
	case types.AttackRiskLow:
		return 3
	default:
		return 4
	}
}
