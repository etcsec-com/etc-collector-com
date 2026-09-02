package types

import "time"

// User represents an Active Directory user
type User struct {
	DN                string `json:"dn"`
	SAMAccountName    string `json:"sAMAccountName"`
	UserPrincipalName string `json:"userPrincipalName,omitempty"`
	DisplayName       string `json:"displayName,omitempty"`
	Description       string `json:"description,omitempty"`
	Mail              string `json:"mail,omitempty"`
	// HR/Profile fields for detailed affectedEntities
	Title                      string    `json:"title,omitempty"`
	Department                 string    `json:"department,omitempty"`
	Company                    string    `json:"company,omitempty"`
	Manager                    string    `json:"manager,omitempty"`
	PhysicalDeliveryOfficeName string    `json:"physicalDeliveryOfficeName,omitempty"`
	EmployeeID                 string    `json:"employeeID,omitempty"`
	TelephoneNumber            string    `json:"telephoneNumber,omitempty"`
	Disabled                   bool      `json:"disabled"`
	LockedOut                  bool      `json:"lockedOut"`
	PasswordNeverExpires       bool      `json:"passwordNeverExpires"`
	PasswordNotRequired        bool      `json:"passwordNotRequired"`
	PasswordExpired            bool      `json:"passwordExpired"`
	CannotChangePassword       bool      `json:"cannotChangePassword"`
	DoesNotRequirePreAuth      bool      `json:"doesNotRequirePreAuth"`
	TrustedForDelegation       bool      `json:"trustedForDelegation"`
	TrustedToAuthForDelegation bool      `json:"trustedToAuthForDelegation"`
	UseDesKeyOnly              bool      `json:"useDesKeyOnly"`
	AdminCount                 bool      `json:"adminCount"`
	Created                    time.Time `json:"created"`
	WhenChanged                time.Time `json:"whenChanged,omitempty"`
	LastLogon                  time.Time `json:"lastLogon"`
	LastLogonTimestamp         time.Time `json:"lastLogonTimestamp"`
	PasswordLastSet            time.Time `json:"passwordLastSet"`
	AccountExpires             time.Time `json:"accountExpires,omitempty"`
	LockoutTime                time.Time `json:"lockoutTime,omitempty"`
	LogonCount                 int       `json:"logonCount"`
	BadPasswordCount           int       `json:"badPasswordCount"`
	PrimaryGroupID             int       `json:"primaryGroupId"`
	UserAccountControl         int       `json:"userAccountControl"`
	MemberOf                   []string  `json:"memberOf,omitempty"`
	SIDHistory                 []string  `json:"sidHistory,omitempty"`
	ServicePrincipalNames      []string  `json:"servicePrincipalNames,omitempty"`
	AllowedToDelegateTo        []string  `json:"msDS-AllowedToDelegateTo,omitempty"`
	SupportedEncryptionTypes   int       `json:"msDS-SupportedEncryptionTypes,omitempty"`
	ObjectSID                  string    `json:"objectSid"`
	// Additional fields for advanced detectors
	ScriptPath                          string `json:"scriptPath,omitempty"`
	KeyCredentialLink                   []byte `json:"msDS-KeyCredentialLink,omitempty"`
	AllowedToActOnBehalfOfOtherIdentity []byte `json:"msDS-AllowedToActOnBehalfOfOtherIdentity,omitempty"`
	// gMSA fields
	IsGMSA                         bool     `json:"isGMSA,omitempty"`
	GMSAMembership                 []byte   `json:"gmsaMembership,omitempty"` // msDS-GroupMSAMembership binary SD
	HasSeEnableDelegationPrivilege bool     `json:"hasSeEnableDelegationPrivilege,omitempty"`
	HasDCSyncRights                bool     `json:"hasDCSyncRights,omitempty"`
	AltSecurityIdentities          []string `json:"altSecurityIdentities,omitempty"`
	// Unix/legacy password attributes (presence detection only)
	UnixUserPassword bool `json:"unixUserPassword,omitempty"`
	UserPassword     bool `json:"userPassword,omitempty"`
	// ACL analysis fields
	HasWriteDACL  bool `json:"hasWriteDACL,omitempty"`
	HasGenericAll bool `json:"hasGenericAll,omitempty"`
	HasWriteOwner bool `json:"hasWriteOwner,omitempty"`

	// Azure-specific fields (only populated for Azure AD users)
	AzureUserType                         *string    `json:"azureUserType,omitempty"` // Member, Guest
	AzureAccountEnabled                   *bool      `json:"azureAccountEnabled,omitempty"`
	AzureLastSignInDateTime               *time.Time `json:"azureLastSignInDateTime,omitempty"`
	AzureLastNonInteractiveSignInDateTime *time.Time `json:"azureLastNonInteractiveSignInDateTime,omitempty"`
	AzureMfaRegistered                    *bool      `json:"azureMfaRegistered,omitempty"`
	AzureJobTitle                         *string    `json:"azureJobTitle,omitempty"`
	AzureOfficeLocation                   *string    `json:"azureOfficeLocation,omitempty"`
	AzureCreatedDateTime                  *time.Time `json:"azureCreatedDateTime,omitempty"`
	AzureCreationType                     *string    `json:"azureCreationType,omitempty"`          // Invitation, EmailVerified, EmailUnverified, Resource, "" (regular cloud-created)
	AzureUsageLocation                    *string    `json:"azureUsageLocation,omitempty"`         // Country code for licensing
	AzureProxyAddresses                   []string   `json:"azureProxyAddresses,omitempty"`        // Secondary email addresses
	AzureOnPremisesSyncEnabled            *bool      `json:"azureOnPremisesSyncEnabled,omitempty"` // Hybrid sync status
	AzureAssignedLicenses                 []string   `json:"azureAssignedLicenses,omitempty"`      // License SKU IDs
	AzureAuthenticationMethods            []string   `json:"azureAuthenticationMethods,omitempty"` // Registered authentication methods (mfa, fido2, phone, etc.)

	// v3.1.38 §2 — Hybrid edges Entra ↔ AD. Populated from Graph
	// /users $select=onPremises* on tenants with Entra Connect sync.
	// Nil for cloud-only users. Used by audit.hybridLinks to cross-ref
	// Entra users with their AD source for hybrid attack-path analysis.
	AzureOnPremisesDistinguishedName  *string `json:"azureOnPremisesDistinguishedName,omitempty"`
	AzureOnPremisesSecurityIdentifier *string `json:"azureOnPremisesSecurityIdentifier,omitempty"`
	AzureOnPremisesImmutableID        *string `json:"azureOnPremisesImmutableId,omitempty"`
	AzureOnPremisesSamAccountName     *string `json:"azureOnPremisesSamAccountName,omitempty"`
}

// Enabled returns true if the user account is not disabled
func (u User) Enabled() bool {
	return !u.Disabled
}

// Group represents an Active Directory group
type Group struct {
	DN                string    `json:"dn"`
	DistinguishedName string    `json:"distinguishedName,omitempty"` // Alias for DN
	CN                string    `json:"cn,omitempty"`
	SAMAccountName    string    `json:"sAMAccountName"`
	DisplayName       string    `json:"displayName,omitempty"`
	Description       string    `json:"description,omitempty"`
	GroupType         int       `json:"groupType"`
	AdminCount        bool      `json:"adminCount"`
	Members           []string  `json:"members,omitempty"`
	Member            []string  `json:"member,omitempty"` // Alias for Members (raw LDAP attr)
	MemberOf          []string  `json:"memberOf,omitempty"`
	ObjectSID         string    `json:"objectSid"`
	Created           time.Time `json:"created,omitempty"`

	// Azure-specific fields (only populated for Azure AD groups)
	AzureGroupTypes                    []string   `json:"azureGroupTypes,omitempty"` // Unified, DynamicMembership
	AzureSecurityEnabled               *bool      `json:"azureSecurityEnabled,omitempty"`
	AzureMailEnabled                   *bool      `json:"azureMailEnabled,omitempty"`
	AzureMembershipRule                *string    `json:"azureMembershipRule,omitempty"`
	AzureMembershipRuleProcessingState *string    `json:"azureMembershipRuleProcessingState,omitempty"`
	AzureIsAssignableToRole            *bool      `json:"azureIsAssignableToRole,omitempty"`
	AzureVisibility                    *string    `json:"azureVisibility,omitempty"` // Public, Private, HiddenMembership
	AzureCreatedDateTime               *time.Time `json:"azureCreatedDateTime,omitempty"`
	AzureOnPremisesSyncEnabled         *bool      `json:"azureOnPremisesSyncEnabled,omitempty"`
	AzureExternalMembersCount          *int       `json:"azureExternalMembersCount,omitempty"` // Count of guest users in the group
}

// Computer represents an Active Directory computer
type Computer struct {
	DN                                  string    `json:"dn"`
	DistinguishedName                   string    `json:"distinguishedName,omitempty"` // Alias for DN
	SAMAccountName                      string    `json:"sAMAccountName"`
	DNSHostName                         string    `json:"dnsHostName,omitempty"`
	OperatingSystem                     string    `json:"operatingSystem,omitempty"`
	OperatingSystemVersion              string    `json:"operatingSystemVersion,omitempty"`
	Description                         string    `json:"description,omitempty"`
	Disabled                            bool      `json:"disabled"`
	TrustedForDelegation                bool      `json:"trustedForDelegation"`
	TrustedToAuthForDelegation          bool      `json:"trustedToAuthForDelegation"`
	AdminCount                          bool      `json:"adminCount,omitempty"`
	Created                             time.Time `json:"created"`
	WhenChanged                         time.Time `json:"whenChanged,omitempty"`
	LastLogon                           time.Time `json:"lastLogon"`
	LastLogonTimestamp                  time.Time `json:"lastLogonTimestamp"`
	PasswordLastSet                     time.Time `json:"passwordLastSet"`
	UserAccountControl                  int       `json:"userAccountControl"`
	SupportedEncryptionTypes            int       `json:"msDS-SupportedEncryptionTypes,omitempty"`
	ServicePrincipalNames               []string  `json:"servicePrincipalNames,omitempty"`
	MemberOf                            []string  `json:"memberOf,omitempty"`
	AllowedToDelegateTo                 []string  `json:"msDS-AllowedToDelegateTo,omitempty"`
	AllowedToActOnBehalfOfOtherIdentity []byte    `json:"msDS-AllowedToActOnBehalfOfOtherIdentity,omitempty"`
	ObjectSID                           string    `json:"objectSid"`
	// Security analysis fields
	ReplicationRights  bool `json:"replicationRights,omitempty"`  // Has DCSync rights
	DangerousACL       bool `json:"dangerousACL,omitempty"`       // Has dangerous ACLs
	SMBSigningDisabled bool `json:"smbSigningDisabled,omitempty"` // SMB signing not required
	// LAPS fields.
	//
	// The three password fields carry cleartext local-administrator passwords
	// read from AD (ms-Mcs-AdmPwd / msLAPS-Password). They are `json:"-"` on
	// purpose: the LAPS detectors evaluate them in-process, but the values must
	// never leave the host — not in the audit report, not in a SaaS payload,
	// not in a debug dump. HasLegacyLAPS / HasWindowsLAPS carry the serialisable
	// presence signal. Do not re-add a json tag here.
	LAPSPassword                    string    `json:"-"` // Only if readable (legacy or Windows LAPS)
	LAPSPasswordExpiry              time.Time `json:"lapsPasswordExpiry,omitempty"`
	HasLegacyLAPS                   bool      `json:"hasLegacyLAPS,omitempty"`  // ms-Mcs-AdmPwd or expiry exists
	HasWindowsLAPS                  bool      `json:"hasWindowsLAPS,omitempty"` // msLAPS-Password or expiry exists
	LegacyLAPSPassword              string    `json:"-"`
	WindowsLAPSPassword             string    `json:"-"`
	LAPSPasswordExcessiveReaders    bool      `json:"lapsPasswordExcessiveReaders,omitempty"`
	LAPSPasswordReadableByNonAdmins bool      `json:"lapsPasswordReadableByNonAdmins,omitempty"`
	// RODC credential caching attributes (msDS-RevealedList, msDS-NeverRevealGroup, msDS-AuthenticatedToAccountList)
	IsRODC                     bool     `json:"isRODC,omitempty"`
	RevealedList               []string `json:"msDS-RevealedList,omitempty"`
	NeverRevealGroup           []string `json:"msDS-NeverRevealGroup,omitempty"`
	AuthenticatedToAccountList []string `json:"msDS-AuthenticatedToAccountList,omitempty"`
}

// Enabled returns true if the computer account is not disabled
func (c Computer) Enabled() bool {
	return !c.Disabled
}

// GPO represents a Group Policy Object
type GPO struct {
	DN                string   `json:"dn"`
	DistinguishedName string   `json:"distinguishedName,omitempty"` // Alias for DN
	CN                string   `json:"cn,omitempty"`                // Common name (GUID format)
	Name              string   `json:"name"`
	DisplayName       string   `json:"displayName"`
	GUID              string   `json:"guid"`
	FilePath          string   `json:"filePath"`
	Enabled           bool     `json:"enabled"`
	UserEnabled       bool     `json:"userEnabled"`
	ComputerEnabled   bool     `json:"computerEnabled"`
	Flags             int      `json:"flags,omitempty"`      // GPO flags (0=enabled, 1=user disabled, 2=computer disabled, 3=all disabled)
	HasWeakACL        bool     `json:"hasWeakACL,omitempty"` // True if non-admins have write access
	LinkedOUs         []string `json:"linkedOUs,omitempty"`
	CSEGuids          []string `json:"cseGuids,omitempty"` // Client-Side Extensions GUIDs
}

// OU represents an Organizational Unit
type OU struct {
	DN                string    `json:"dn"`
	DistinguishedName string    `json:"distinguishedName,omitempty"` // Alias for DN
	Name              string    `json:"name"`
	Description       string    `json:"description,omitempty"`
	Created           time.Time `json:"created,omitempty"`
	Modified          time.Time `json:"modified,omitempty"`
	GPOLinks          []string  `json:"gpoLinks,omitempty"` // Linked GPO GUIDs
}

// Trust represents a domain trust
type Trust struct {
	Name                 string `json:"name,omitempty"` // Alias for TargetDomain
	SourceDomain         string `json:"sourceDomain"`
	TargetDomain         string `json:"targetDomain"`
	TrustType            string `json:"trustType"`                   // Parent, Child, External, Forest
	TrustDirection       string `json:"trustDirection"`              // Inbound, Outbound, Bidirectional
	Direction            string `json:"direction,omitempty"`         // Alias for TrustDirection
	TrustDirectionInt    int    `json:"trustDirectionInt,omitempty"` // Numeric: 1=Inbound, 2=Outbound, 3=Bidirectional
	SIDFiltering         bool   `json:"sidFiltering"`
	SIDFilteringEnabled  bool   `json:"sidFilteringEnabled,omitempty"` // Alias
	SelectiveAuth        bool   `json:"selectiveAuth"`
	SelectiveAuthEnabled bool   `json:"selectiveAuthEnabled,omitempty"` // Alias
	// Encryption settings
	AESEnabled   bool   `json:"aesEnabled,omitempty"`
	RC4Enabled   bool   `json:"rc4Enabled,omitempty"`
	IsTransitive bool   `json:"isTransitive,omitempty"`
	WhenCreated  string `json:"whenCreated,omitempty"`

	// v3.1.18 — real password rotation timestamp from the trustedDomain object
	// (Windows updates this every 30 days by default through the inter-domain
	// trust password change). Used by ANSSI R42 to flag broken rotation.
	PasswordLastSet time.Time `json:"passwordLastSet,omitempty"`
}

// DomainInfo represents domain-level information
type DomainInfo struct {
	DN                    string   `json:"dn"` // Alias for DomainDN
	DomainDN              string   `json:"domainDN"`
	DomainSID             string   `json:"domainSid"`
	DomainName            string   `json:"domainName"`
	ForestName            string   `json:"forestName"`
	FunctionalLevel       string   `json:"functionalLevel"`
	FunctionalLevelInt    int      `json:"functionalLevelInt,omitempty"` // Numeric version for comparisons
	ForestFunctionalLevel string   `json:"forestFunctionalLevel"`
	DomainControllers     []string `json:"domainControllers"`

	// Policy settings - Password Policy
	MinPasswordLength     int `json:"minPasswordLength"`
	MinPwdLength          int `json:"minPwdLength,omitempty"` // Alias
	PasswordHistoryLength int `json:"passwordHistoryLength"`
	PwdHistoryLength      int `json:"pwdHistoryLength,omitempty"` // Alias
	MaxPasswordAge        int `json:"maxPasswordAge"`             // days
	MaxPwdAge             int `json:"maxPwdAge,omitempty"`        // Alias (days)
	MinPwdAge             int `json:"minPwdAge,omitempty"`        // Minimum password age (days)

	// Policy settings - Lockout
	LockoutThreshold int `json:"lockoutThreshold"`
	LockoutDuration  int `json:"lockoutDuration"` // minutes

	// Policy settings - Kerberos
	MaxTicketAge        int `json:"maxTicketAge,omitempty"` // hours
	MaxRenewAge         int `json:"maxRenewAge,omitempty"`  // days
	MachineAccountQuota int `json:"machineAccountQuota"`

	// Security settings
	AnonymousLDAPAllowed   bool   `json:"anonymousLdapAllowed,omitempty"`
	RecycleBinEnabled      bool   `json:"recycleBinEnabled,omitempty"`
	AdminSDHolderModified  bool   `json:"adminSdHolderModified,omitempty"`
	DsHeuristics           string `json:"dsHeuristics,omitempty"`
	LDAPSigningRequired    bool   `json:"ldapSigningRequired,omitempty"`
	ChannelBindingRequired bool   `json:"channelBindingRequired,omitempty"`

	// Statistics
	ForeignSecurityPrincipalsCount int `json:"foreignSecurityPrincipalsCount,omitempty"`

	// Domain metadata (PingCastle parity)
	SchemaVersion         int        `json:"schemaVersion,omitempty"`         // AD Schema objectVersion (e.g., 88=Win2022)
	DomainCreated         time.Time  `json:"domainCreated,omitempty"`         // whenCreated on domain object
	NetBIOSName           string     `json:"netBIOSName,omitempty"`           // nETBIOSName from Partitions
	KrbtgtPasswordLastSet time.Time  `json:"krbtgtPasswordLastSet,omitempty"` // pwdLastSet on krbtgt account
	KrbtgtKeyVersion      int        `json:"krbtgtKeyVersion,omitempty"`      // msDS-KeyVersionNumber on krbtgt
	LastADBackupDate      *time.Time `json:"lastADBackupDate,omitempty"`      // Last AD backup from NTDS metadata
	HasKdsRootKey         bool       `json:"hasKdsRootKey,omitempty"`         // KDS root key provisioned (gMSA prereq)
	DisabledUsersCount    int        `json:"disabledUsersCount,omitempty"`    // Count of disabled user accounts
	DCCount               int        `json:"dcCount,omitempty"`               // Total number of domain controllers

	// Extended domain metadata (PingCastle full parity)
	ForestFQDN                   string    `json:"forestFQDN,omitempty"`                   // Forest DNS name (e.g., "contoso.com")
	ForestFunctionalLevelInt     int       `json:"forestFunctionalLevelInt,omitempty"`     // Numeric forest functional level
	GuestEnabled                 bool      `json:"guestEnabled,omitempty"`                 // Guest account is enabled
	AdminLastLoginDate           time.Time `json:"adminLastLoginDate,omitempty"`           // Built-in Administrator last logon
	AdminAccountName             string    `json:"adminAccountName,omitempty"`             // Built-in Administrator sAMAccountName
	ExchangeSchemaVersion        int       `json:"exchangeSchemaVersion,omitempty"`        // Exchange schema version (0=not installed)
	UsingNTFRSForSYSVOL          bool      `json:"usingNTFRSForSYSVOL,omitempty"`          // SYSVOL replication uses NTFRS (not DFSR)
	LAPSSchemaInstalled          bool      `json:"lapsSchemaInstalled,omitempty"`          // Legacy LAPS schema (ms-Mcs-AdmPwd)
	NewLAPSSchemaInstalled       bool      `json:"newLapsSchemaInstalled,omitempty"`       // Windows LAPS schema (msLAPS-Password)
	PreWin2000AuthenticatedUsers bool      `json:"preWin2000AuthenticatedUsers,omitempty"` // Authenticated Users in Pre-Windows 2000 group
	SitesCount                   int       `json:"sitesCount,omitempty"`                   // Number of AD Sites
	SubnetsCount                 int       `json:"subnetsCount,omitempty"`                 // Number of AD Subnets
}

// CertTemplate represents an AD CS certificate template
type CertTemplate struct {
	DN                      string   `json:"dn"`
	Name                    string   `json:"name"`
	DisplayName             string   `json:"displayName"`
	OID                     string   `json:"oid"`
	EnrollmentFlag          int      `json:"enrollmentFlag"`
	RequiresManagerApproval bool     `json:"requiresManagerApproval"`
	AuthorizedSignatures    int      `json:"authorizedSignatures"`
	SchemaVersion           int      `json:"schemaVersion"`
	ValidityPeriod          string   `json:"validityPeriod"`
	RenewalPeriod           string   `json:"renewalPeriod,omitempty"`
	ExtendedKeyUsage        []string `json:"extendedKeyUsage,omitempty"`
	SubjectNameFlag         int      `json:"subjectNameFlag"`
	CertificateNameFlag     int      `json:"certificateNameFlag,omitempty"` // msPKI-Certificate-Name-Flag

	// v3.1.18 — key strength fields (ANSSI PA-099 R37)
	MinKeyLength int `json:"minKeyLength,omitempty"` // msPKI-Minimal-Key-Size (bits)

	// Security analysis fields
	HasWeakEnrollmentACL    bool `json:"hasWeakEnrollmentACL,omitempty"`
	HasGenericAllPermission bool `json:"hasGenericAllPermission,omitempty"`
	HasWeakACL              bool `json:"hasWeakACL,omitempty"`
}

// EKUNameMap maps EKU OIDs to human-readable names
var EKUNameMap = map[string]string{
	"1.3.6.1.5.5.7.3.1":       "Server Authentication",
	"1.3.6.1.5.5.7.3.2":       "Client Authentication",
	"1.3.6.1.5.5.7.3.3":       "Code Signing",
	"1.3.6.1.5.5.7.3.4":       "Secure Email",
	"1.3.6.1.5.2.3.4":         "PKINIT Client Authentication",
	"1.3.6.1.4.1.311.20.2.1":  "Certificate Request Agent",
	"1.3.6.1.4.1.311.20.2.2":  "Smart Card Logon",
	"2.5.29.37.0":             "Any Purpose",
	"1.3.6.1.5.5.7.3.8":       "Time Stamping",
	"1.3.6.1.5.5.7.3.9":       "OCSP Signing",
	"1.3.6.1.4.1.311.10.3.4":  "Encrypting File System",
	"1.3.6.1.4.1.311.10.3.12": "Document Signing",
}

// ResolveEKUNames converts EKU OIDs to human-readable names
func ResolveEKUNames(oids []string) []string {
	if len(oids) == 0 {
		return nil
	}
	names := make([]string, 0, len(oids))
	for _, oid := range oids {
		if name, ok := EKUNameMap[oid]; ok {
			names = append(names, name)
		} else {
			names = append(names, oid)
		}
	}
	return names
}

// ACE represents an Access Control Entry
type ACE struct {
	Principal           string `json:"principal"`
	PrincipalSID        string `json:"principalSid"`
	AccessMask          int    `json:"accessMask"`
	AceType             string `json:"aceType"`
	ObjectType          string `json:"objectType,omitempty"`
	InheritedObjectType string `json:"inheritedObjectType,omitempty"`
	IsInherited         bool   `json:"isInherited"`
}

// ACLEntry represents an Access Control List entry with its target object
type ACLEntry struct {
	ObjectDN    string `json:"objectDn"`              // DN of the object the ACE applies to
	Trustee     string `json:"trustee"`               // SID or name of the principal
	AccessMask  int    `json:"accessMask"`            // Access mask bits
	AceType     string `json:"aceType"`               // Type of ACE (allow, deny)
	ObjectType  string `json:"objectType,omitempty"`  // GUID of the object type or property
	IsInherited bool   `json:"isInherited,omitempty"` // v3.1.29 — set from AceFlags & 0x10 (INHERITED_ACE)
}
