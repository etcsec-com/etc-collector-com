package types

// AttackNodeType represents node types in the attack graph
type AttackNodeType string

const (
	AttackNodeUser         AttackNodeType = "user"
	AttackNodeGroup        AttackNodeType = "group"
	AttackNodeComputer     AttackNodeType = "computer"
	AttackNodeGPO          AttackNodeType = "gpo"
	AttackNodeOU           AttackNodeType = "ou"
	AttackNodeDomain       AttackNodeType = "domain"
	AttackNodeCertTemplate AttackNodeType = "certTemplate"
)

// AttackPathRisk represents risk levels for attack paths
type AttackPathRisk string

const (
	AttackRiskCritical AttackPathRisk = "critical"
	AttackRiskHigh     AttackPathRisk = "high"
	AttackRiskMedium   AttackPathRisk = "medium"
	AttackRiskLow      AttackPathRisk = "low"
)

// AttackPathType represents types of attack paths
type AttackPathType string

const (
	PathACLAbuse        AttackPathType = "ACL_ABUSE"
	PathKerberoasting   AttackPathType = "KERBEROASTING"
	PathASREPRoasting   AttackPathType = "ASREP_ROASTING"
	PathDelegationAbuse AttackPathType = "DELEGATION_ABUSE"
	PathLateralMovement AttackPathType = "LATERAL_MOVEMENT"
	PathCertAbuse       AttackPathType = "CERTIFICATE_ABUSE"
	PathGroupMembership AttackPathType = "GROUP_MEMBERSHIP"
	PathDCSync          AttackPathType = "DCSYNC"
	PathOwnershipAbuse  AttackPathType = "OWNERSHIP_ABUSE"
	PathSIDHistory      AttackPathType = "SID_HISTORY"
	PathLAPSAbuse       AttackPathType = "LAPS_ABUSE"
	PathGMSAAbuse       AttackPathType = "GMSA_ABUSE"
)

// AttackRelationType represents relation types between nodes
type AttackRelationType string

const (
	RelMemberOf               AttackRelationType = "MemberOf"
	RelGenericAll             AttackRelationType = "GenericAll"
	RelWriteDacl              AttackRelationType = "WriteDacl"
	RelWriteOwner             AttackRelationType = "WriteOwner"
	RelGenericWrite           AttackRelationType = "GenericWrite"
	RelForceChangePassword    AttackRelationType = "ForceChangePassword"
	RelAddMember              AttackRelationType = "AddMember"
	RelDCSync                 AttackRelationType = "DCSync"
	RelAllowedToDelegate      AttackRelationType = "AllowedToDelegate"
	RelAllowedToAct           AttackRelationType = "AllowedToAct"
	RelOwns                   AttackRelationType = "Owns"
	RelAdminTo                AttackRelationType = "AdminTo"
	RelHasSession             AttackRelationType = "HasSession"
	RelCanPSRemote            AttackRelationType = "CanPSRemote"
	RelCanRDP                 AttackRelationType = "CanRDP"
	RelExecuteDCOM            AttackRelationType = "ExecuteDCOM"
	RelSQLAdmin               AttackRelationType = "SQLAdmin"
	RelReadLAPSPassword       AttackRelationType = "ReadLAPSPassword"
	RelReadGMSAPassword       AttackRelationType = "ReadGMSAPassword"
	RelContains               AttackRelationType = "Contains"
	RelGPLink                 AttackRelationType = "GPLink"
	RelTrustedBy              AttackRelationType = "TrustedBy"
	RelHasSIDHistory          AttackRelationType = "HasSIDHistory"
	RelWriteKeyCredentialLink AttackRelationType = "WriteKeyCredentialLink"
	RelEnroll                 AttackRelationType = "Enroll"
)

// Well-known ACL GUIDs for extended rights
const (
	GUIDForceChangePassword             = "00299570-246d-11d0-a768-00aa006e0529"
	GUIDDSReplicationGetChanges         = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
	GUIDDSReplicationGetChangesAll      = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"
	GUIDDSReplicationGetChangesFiltered = "89e95b76-444d-4c62-991a-0facbeda640c"
	GUIDSelfMembership                  = "bf9679c0-0de6-11d0-a285-00aa003049e2"
	GUIDLAPSPassword                    = "e91556f8-b3c8-4b66-b3c8-4b0c8ac2c45b"
	GUIDCertificateEnrollment           = "0e10c968-78fb-11d2-90d4-00c04f79dc55"
	GUIDCertificateAutoenrollment       = "a05b8cc2-17bc-4802-a710-e7c15ab866a2"
	GUIDKeyCredentialLink               = "5b47d60f-6090-40b2-9f37-2a4de88f3063"
)

// Access mask bits for ACL analysis
const (
	MaskGenericRead    = 0x80000000
	MaskGenericWrite   = 0x40000000
	MaskGenericExecute = 0x20000000
	MaskGenericAll     = 0x10000000
	MaskWriteOwner     = 0x00080000
	MaskWriteDACL      = 0x00040000
	MaskWriteProperty  = 0x00000020
	MaskReadProperty   = 0x00000010
	MaskSelf           = 0x00000008
	MaskControlAccess  = 0x00000100
	MaskDelete         = 0x00010000
)

// Well-known privileged SID suffixes (relative to domain SID)
var PrivilegedSIDSuffixes = map[string]string{
	"-512": "Domain Admins",
	"-516": "Domain Controllers",
	"-518": "Schema Admins",
	"-519": "Enterprise Admins",
	"-544": "Administrators",
	"-548": "Account Operators",
	"-549": "Server Operators",
	"-550": "Print Operators",
	"-551": "Backup Operators",
	"-526": "Key Admins",
	"-527": "Enterprise Key Admins",
}

// AttackGraphNode represents a node in the graph
type AttackGraphNode struct {
	ID           string         `json:"id"`
	Name         string         `json:"name"`
	Type         AttackNodeType `json:"type"`
	SID          string         `json:"sid,omitempty"`
	DN           string         `json:"dn,omitempty"`
	Domain       string         `json:"domain,omitempty"`
	IsEnabled    bool           `json:"isEnabled,omitempty"`
	IsPrivileged bool           `json:"isPrivileged,omitempty"`
}

// AttackGraphRelation represents a relation in the chain
type AttackGraphRelation struct {
	Relation    AttackRelationType `json:"relation"`
	IsAbusable  bool               `json:"isAbusable"`
	AccessMask  *int               `json:"accessMask,omitempty"`
	ObjectType  string             `json:"objectType,omitempty"`
	Description string             `json:"description,omitempty"`
}

// AttackEntryPointProperties holds properties of an entry point
type AttackEntryPointProperties struct {
	HasSPN            bool `json:"hasSPN,omitempty"`
	NoPreauth         bool `json:"noPreauth,omitempty"`
	PasswordNotExpire bool `json:"passwordNotExpire,omitempty"`
	Unconstrained     bool `json:"unconstrained,omitempty"`
	Constrained       bool `json:"constrained,omitempty"`
	RBCD              bool `json:"rbcd,omitempty"`
	AdminCount        bool `json:"adminCount,omitempty"`
	Enabled           bool `json:"enabled,omitempty"`
}

// AttackEntryPoint represents the start of an attack path
type AttackEntryPoint struct {
	ID         string                     `json:"id"`
	Name       string                     `json:"name"`
	Type       AttackNodeType             `json:"type"`
	Properties AttackEntryPointProperties `json:"properties"`
}

// AttackPath represents a complete attack path
type AttackPath struct {
	ID          string           `json:"id"`
	Risk        AttackPathRisk   `json:"risk"`
	Type        AttackPathType   `json:"type"`
	Hops        int              `json:"hops"`
	Description string           `json:"description"`
	Chain       []interface{}    `json:"chain"` // alternating AttackGraphNode / AttackGraphRelation
	EntryPoint  AttackEntryPoint `json:"entryPoint"`
	Target      AttackGraphNode  `json:"target"`
	Mitigation  string           `json:"mitigation"`
}

// AttackTarget represents a privileged target
type AttackTarget struct {
	ID     string         `json:"id"`
	Name   string         `json:"name"`
	Type   AttackNodeType `json:"type"`
	SID    string         `json:"sid,omitempty"`
	DN     string         `json:"dn,omitempty"`
	Reason string         `json:"reason"`
}

// AttackTargetStat summarizes how reachable a privileged target is
type AttackTargetStat struct {
	Name       string                 `json:"name"`
	TotalPaths int                    `json:"totalPaths"`
	ByType     map[AttackPathType]int `json:"byType,omitempty"`
}

// AttackGraphStats contains statistics about the attack graph
type AttackGraphStats struct {
	TotalPaths       int                         `json:"totalPaths"`
	TotalCandidates  int                         `json:"totalCandidates"`            // before smart selection
	CandidatesByType map[AttackPathType]int      `json:"candidatesByType,omitempty"` // all candidates per type (before caps)
	ByRisk           map[AttackPathRisk]int      `json:"byRisk"`
	ByType           map[AttackPathType]int      `json:"byType"`
	ByTarget         map[string]AttackTargetStat `json:"byTarget,omitempty"`
	AverageHops      float64                     `json:"averageHops"`
	ShortestPath     int                         `json:"shortestPath"`
	LongestPath      int                         `json:"longestPath"`
}

// AttackGraphUniqueNode represents a node involved in attack paths
type AttackGraphUniqueNode struct {
	ID        string         `json:"id"`
	Name      string         `json:"name"`
	Type      AttackNodeType `json:"type"`
	PathCount int            `json:"pathCount"`
	SID       string         `json:"sid,omitempty"`
}

// AttackGraphExport is the full export format (matches TypeScript)
type AttackGraphExport struct {
	Version     string                  `json:"version"`
	GeneratedAt string                  `json:"generatedAt"`
	Domain      string                  `json:"domain"`
	Targets     []AttackTarget          `json:"targets"`
	Paths       []AttackPath            `json:"paths"`
	Stats       AttackGraphStats        `json:"stats"`
	UniqueNodes []AttackGraphUniqueNode `json:"uniqueNodes"`
}
