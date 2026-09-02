// Package types defines common types used across the application
package types

import (
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"time"
)

// Severity represents the severity level of a finding
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// Weight returns the scoring weight for this severity (aligned with TypeScript v1.1.0)
func (s Severity) Weight() float64 {
	switch s {
	case SeverityCritical:
		return 10
	case SeverityHigh:
		return 3
	case SeverityMedium:
		return 1
	case SeverityLow:
		return 0.2
	default:
		return 0
	}
}

// ComplianceMapping ties a finding to one or more framework controls.
//
// A single finding may satisfy several framework controls simultaneously
// (e.g. PASSWORD_REVERSIBLE_ENCRYPTION → ANSSI R1 + HDS 5.5 + RGPD art.32(1)(a)).
// Mappings are populated by audit/compliance.EnrichWithCompliance just before
// the engine returns its result; detectors don't carry framework knowledge.
//
// Severity may override the finding's severity in the context of a specific
// framework (a low-severity hygiene finding can be high-severity for HDS).
type ComplianceMapping struct {
	Framework string `json:"framework"`          // e.g. "ANSSI_PA022", "HDS_v1_1", "RGPD"
	Control   string `json:"control"`            // e.g. "R12", "5.1.4", "art.32(1)(b)"
	Severity  string `json:"severity,omitempty"` // optional per-framework severity override
}

// Finding represents a security finding
type Finding struct {
	Type             string                 `json:"type"`
	Severity         Severity               `json:"severity"`
	Category         string                 `json:"category"`
	Title            string                 `json:"title"`
	Description      string                 `json:"description"`
	Count            int                    `json:"count"`
	TotalInstances   int                    `json:"totalInstances,omitempty"`
	AffectedEntities []AffectedEntity       `json:"affectedEntities,omitempty"`
	Details          map[string]interface{} `json:"details,omitempty"`
	// Compliance lists the framework controls satisfied (or violated) by this
	// finding. Empty for non-compliance-relevant findings. omitempty keeps the
	// JSON shape stable for existing consumers.
	Compliance []ComplianceMapping `json:"compliance,omitempty"`

	// v3.1.19 — Reproducibility lets an ANSSI auditor replay the LDAP query
	// or SYSVOL inspection that produced this finding. Populated by ANSSI
	// detectors that operate purely on LDAP attributes; left nil when the
	// reproduction recipe is too complex or non-deterministic (e.g. requires
	// SMB+SYSVOL combined data).
	Reproducibility *FindingReproducibility `json:"reproducibility,omitempty"`
}

// FindingReproducibility describes how to manually reproduce the verdict
// of a Finding. Optional — only populated by detectors that have a clean
// LDAP query equivalent.
type FindingReproducibility struct {
	LDAPBaseDN string   `json:"ldapBaseDN,omitempty"`
	LDAPFilter string   `json:"ldapFilter,omitempty"` // RFC 4515 syntax
	LDAPAttrs  []string `json:"ldapAttrs,omitempty"`
	Notes      string   `json:"notes,omitempty"` // free-form for non-LDAP detectors
}

// AzureEntityFields contains Azure-specific fields for affected entities
type AzureEntityFields struct {
	// User fields (haute priorité)
	UserType                         *string    `json:"userType,omitempty"` // Member, Guest
	AccountEnabled                   *bool      `json:"accountEnabled,omitempty"`
	LastSignInDateTime               *time.Time `json:"lastSignInDateTime,omitempty"`
	LastNonInteractiveSignInDateTime *time.Time `json:"lastNonInteractiveSignInDateTime,omitempty"`
	MfaRegistered                    *bool      `json:"mfaRegistered,omitempty"`
	RiskLevel                        *string    `json:"riskLevel,omitempty"` // low, medium, high, hidden, none
	RiskState                        *string    `json:"riskState,omitempty"` // atRisk, confirmedCompromised, remediated, dismissed
	UsageLocation                    *string    `json:"usageLocation,omitempty"`
	ProxyAddresses                   []string   `json:"proxyAddresses,omitempty"`
	OnPremisesSyncEnabled            *bool      `json:"onPremisesSyncEnabled,omitempty"`
	AssignedLicenses                 []string   `json:"assignedLicenses,omitempty"`      // License SKU IDs
	AuthenticationMethods            []string   `json:"authenticationMethods,omitempty"` // Registered authentication methods

	// User fields (moyenne priorité)
	JobTitle              *string    `json:"jobTitle,omitempty"`
	OfficeLocation        *string    `json:"officeLocation,omitempty"`
	CreatedDateTime       *time.Time `json:"createdDateTime,omitempty"`
	SignInSessionsRevoked *bool      `json:"signInSessionsRevoked,omitempty"`

	// Group fields (haute priorité)
	GroupTypes                    []string `json:"groupTypes,omitempty"` // Unified, DynamicMembership
	SecurityEnabled               *bool    `json:"securityEnabled,omitempty"`
	MembershipRuleProcessingState *string  `json:"membershipRuleProcessingState,omitempty"`
	IsAssignableToRole            *bool    `json:"isAssignableToRole,omitempty"`
	OwnerCount                    *int     `json:"ownerCount,omitempty"`

	// Group fields (moyenne priorité)
	Visibility                 *string `json:"visibility,omitempty"` // Public, Private, HiddenMembership
	MailEnabled                *bool   `json:"mailEnabled,omitempty"`
	MembershipRule             *string `json:"membershipRule,omitempty"`
	GroupOnPremisesSyncEnabled *bool   `json:"groupOnPremisesSyncEnabled,omitempty"`
	ExternalMembersCount       *int    `json:"externalMembersCount,omitempty"` // Count of guest users

	// Application fields (haute priorité)
	AppId                 *string    `json:"appId,omitempty"`
	SignInAudience        *string    `json:"signInAudience,omitempty"`
	HasExpiredCredentials *bool      `json:"hasExpiredCredentials,omitempty"`
	DangerousPermissions  []string   `json:"dangerousPermissions,omitempty"`
	ApiPermissions        []string   `json:"apiPermissions,omitempty"` // all permissions, human-readable
	AppOwnerCount         *int       `json:"appOwnerCount,omitempty"`
	Owners                []string   `json:"owners,omitempty"`                // displayNames
	CredentialExpiryDate  *time.Time `json:"credentialExpiryDate,omitempty"`  // earliest expiry
	AppLastSignInDateTime *time.Time `json:"appLastSignInDateTime,omitempty"` // app/SP-level sign-in

	// Application fields (moyenne priorité)
	PublisherDomain      *string `json:"publisherDomain,omitempty"`
	Homepage             *string `json:"homepage,omitempty"`
	LogoutUrl            *string `json:"logoutUrl,omitempty"`
	ImplicitGrantEnabled *bool   `json:"implicitGrantEnabled,omitempty"`
	CredentialCount      *int    `json:"credentialCount,omitempty"`

	// ServicePrincipal fields (haute priorité)
	ServicePrincipalType      *string `json:"servicePrincipalType,omitempty"` // Application, ManagedIdentity, Legacy
	IsFirstParty              *bool   `json:"isFirstParty,omitempty"`
	AppRoleAssignmentsCount   *int    `json:"appRoleAssignmentsCount,omitempty"`
	AppRoleAssignmentRequired *bool   `json:"appRoleAssignmentRequired,omitempty"`

	// ServicePrincipal fields (moyenne priorité)
	AppOwnerOrganizationId             *string `json:"appOwnerOrganizationId,omitempty"`
	PreferredTokenSigningKeyThumbprint *string `json:"preferredTokenSigningKeyThumbprint,omitempty"`

	// ConditionalAccess fields (haute priorité)
	State         *string  `json:"state,omitempty"`         // enabled, disabled, enabledForReportingButNotEnforced
	Conditions    *string  `json:"conditions,omitempty"`    // JSON summary of conditions
	GrantControls []string `json:"grantControls,omitempty"` // mfa, compliantDevice, etc.

	// ConditionalAccess fields (moyenne priorité)
	UserRiskLevels   []string `json:"userRiskLevels,omitempty"`
	SignInRiskLevels []string `json:"signInRiskLevels,omitempty"`
	IncludeUsers     []string `json:"includeUsers,omitempty"`
	ExcludeUsers     []string `json:"excludeUsers,omitempty"`
	IncludeApps      []string `json:"includeApps,omitempty"`

	// RoleAssignment fields
	RoleName               *string    `json:"roleName,omitempty"`
	RoleDefinitionId       *string    `json:"roleDefinitionId,omitempty"`
	PrincipalType          *string    `json:"principalType,omitempty"` // User, Group, ServicePrincipal
	PrincipalUpn           *string    `json:"principalUpn,omitempty"`  // UPN if principal is a User
	PrincipalMail          *string    `json:"principalMail,omitempty"`
	PrincipalJobTitle      *string    `json:"principalJobTitle,omitempty"`
	PrincipalDepartment    *string    `json:"principalDepartment,omitempty"`
	PrincipalLastSignIn    *time.Time `json:"principalLastSignIn,omitempty"` // principal last sign-in
	PrincipalMfaRegistered *bool      `json:"principalMfaRegistered,omitempty"`
	PrincipalRiskLevel     *string    `json:"principalRiskLevel,omitempty"`
	IsPermanent            *bool      `json:"isPermanent,omitempty"`
	AssignmentScope        *string    `json:"assignmentScope,omitempty"`
	// PIM (Privileged Identity Management) fields
	AssignmentType        *string    `json:"assignmentType,omitempty"`        // direct, eligible, activated
	MemberType            *string    `json:"memberType,omitempty"`            // direct, inherited
	ActivationDuration    *string    `json:"activationDuration,omitempty"`    // e.g., "PT8H" for 8 hours
	ActivatedAt           *time.Time `json:"activatedAt,omitempty"`           // when activation started
	ExpirationDateTime    *time.Time `json:"expirationDateTime,omitempty"`    // when activation expires
	Justification         *string    `json:"justification,omitempty"`         // Activation justification
	TicketInfo            *string    `json:"ticketInfo,omitempty"`            // Ticket number/system
	IsEligible            *bool      `json:"isEligible,omitempty"`            // True if PIM-eligible
	RequiresJustification *bool      `json:"requiresJustification,omitempty"` // PIM policy setting
	RequiresApproval      *bool      `json:"requiresApproval,omitempty"`      // PIM policy setting

	// OAuth2Grant fields
	ConsentType        *string `json:"consentType,omitempty"` // AllPrincipals, Principal
	Scope              *string `json:"scope,omitempty"`
	ResourceName       *string `json:"resourceName,omitempty"`       // e.g. "Microsoft Graph"
	ClientAppId        *string `json:"clientAppId,omitempty"`        // appId of consented app
	PermissionCategory *string `json:"permissionCategory,omitempty"` // Delegated / Application

	// Sign-in risk detector fields. These are merged flat into the affected
	// entity JSON by the custom Azure marshalers so SaaS can consume the
	// detector-specific evidence without a nested schema migration.
	SignInRiskContext map[string]any `json:"signInRiskContext,omitempty"`
}

// CertTemplateFields holds ADCS certificate template security attributes
type CertTemplateFields struct {
	DisplayName             string                   `json:"displayName,omitempty"`
	OID                     string                   `json:"oid,omitempty"`
	SchemaVersion           int                      `json:"schemaVersion,omitempty"`
	SubjectNameFlag         int                      `json:"subjectNameFlag,omitempty"`
	EnrollmentFlag          int                      `json:"enrollmentFlag,omitempty"`
	AuthorizedSignatures    int                      `json:"authorizedSignatures,omitempty"`
	ValidityPeriod          string                   `json:"validityPeriod,omitempty"`
	RenewalPeriod           string                   `json:"renewalPeriod,omitempty"`
	EnrolleeSuppliesSubject bool                     `json:"enrolleeSuppliesSubject"`
	RequiresManagerApproval bool                     `json:"requiresManagerApproval"`
	ClientAuthentication    bool                     `json:"clientAuthentication"`
	AnyPurpose              bool                     `json:"anyPurpose"`
	EnrollmentAgent         bool                     `json:"enrollmentAgent"`
	EKUs                    []string                 `json:"ekus,omitempty"`
	EKUNames                []string                 `json:"ekuNames,omitempty"`
	Owner                   string                   `json:"owner,omitempty"`
	Permissions             []CertTemplatePermission `json:"permissions,omitempty"`
}

// CertTemplatePermission represents a dangerous permission on a certificate template
type CertTemplatePermission struct {
	Trustee    string `json:"trustee"`
	AccessMask int    `json:"accessMask"`
	AceType    string `json:"aceType"`
	Right      string `json:"right,omitempty"`
}

// EntityRef is a lightweight reference used to point at another entity from
// inside an AffectedEntity. Currently only used by aclEntry (trustee + target).
// Type is required; sid/dn/name are optional depending on what's known.
type EntityRef struct {
	Type string `json:"type"`
	DN   string `json:"dn,omitempty"`
	SID  string `json:"sid,omitempty"`
	Name string `json:"name,omitempty"`
}

// AffectedEntity represents an affected AD object (TypeScript-compatible format)
type AffectedEntity struct {
	Type           string `json:"type"` // "user", "group", "computer", "gpo", "site", "trust", "application", "servicePrincipal", "conditionalAccessPolicy", "roleAssignment", "oauth2Grant"
	DN             string `json:"dn"`
	SAMAccountName string `json:"sAMAccountName"`

	// User profile fields (TypeScript format)
	UserPrincipalName          string `json:"userPrincipalName,omitempty"`
	DisplayName                string `json:"displayName,omitempty"`
	Mail                       string `json:"mail,omitempty"`
	Title                      string `json:"title,omitempty"`
	Department                 string `json:"department,omitempty"`
	Company                    string `json:"company,omitempty"`
	Manager                    string `json:"manager,omitempty"`
	PhysicalDeliveryOfficeName string `json:"physicalDeliveryOfficeName,omitempty"`
	Description                string `json:"description,omitempty"`
	EmployeeID                 string `json:"employeeID,omitempty"`
	TelephoneNumber            string `json:"telephoneNumber,omitempty"`

	// Timestamps (TypeScript format - nullable)
	WhenCreated     string  `json:"whenCreated,omitempty"`
	WhenChanged     string  `json:"whenChanged,omitempty"`
	LastLogon       *string `json:"lastLogon"`      // null if never logged on
	PasswordLastSet *string `json:"pwdLastSet"`     // null if never set
	AccountExpires  *string `json:"accountExpires"` // null if never expires
	LockoutTime     *string `json:"lockoutTime"`    // null if not locked

	// Account status (TypeScript format)
	BadPwdCount int      `json:"badPwdCount"`
	AdminCount  int      `json:"adminCount"` // 0 or 1 (not bool)
	MemberOf    []string `json:"memberOf"`
	Enabled     bool     `json:"enabled"`

	// Computer-specific
	OperatingSystem        string `json:"operatingSystem,omitempty"`
	OperatingSystemVersion string `json:"operatingSystemVersion,omitempty"`
	DNSHostName            string `json:"dnsHostName,omitempty"`

	// Group-specific
	MemberCount int      `json:"memberCount,omitempty"`
	Members     []string `json:"members,omitempty"` // List of member DNs (AD) / object IDs (Entra)

	// Generic name field for GPOs, trusts, etc.
	Name string `json:"name,omitempty"`

	// Domain-specific (populated only when Type == "domain")
	NetBIOSName           string `json:"netbiosName,omitempty"`
	DomainSID             string `json:"domainSid,omitempty"`
	ForestRoot            string `json:"forestRoot,omitempty"`
	FunctionalLevel       string `json:"functionalLevel,omitempty"`
	DomainControllerCount int    `json:"domainControllerCount,omitempty"`

	// Principal / wellKnownSid-specific (v3.1.29 §3)
	SID        string `json:"sid,omitempty"`
	Scope      string `json:"scope,omitempty"` // "BuiltinDomain" | "WellKnown" | "Domain"
	Unresolved bool   `json:"unresolved,omitempty"`

	// ACL entry-specific (v3.1.29 §4) — populated only when Type == "aclEntry"
	Trustee     *EntityRef `json:"trustee,omitempty"`
	Right       string     `json:"right,omitempty"`
	Target      *EntityRef `json:"target,omitempty"`
	Inheritance string     `json:"inheritance,omitempty"` // "explicit" | "inherited"

	// DC-specific (v3.1.29 §5) — populated only when Type == "dc"
	FSMORoles           []string `json:"fsmoRoles,omitempty"`
	IsReadOnlyDC        bool     `json:"isReadOnlyDC,omitempty"`
	Site                string   `json:"site,omitempty"`
	ReplicationPartners []string `json:"replicationPartners,omitempty"`

	// GPO/OU inventory-specific (T_003, asset-entities P2 §6) — populated only
	// by the eager INFO_DOMAIN_GPO_INVENTORY / INFO_DOMAIN_OU_INVENTORY
	// detectors so the SaaS /assets/gpos and /assets/ous pages can list every
	// GPO/OU on well-configured domains (not just those referenced by a
	// finding). The inventory detectors initialise every slice non-nil, so the
	// emitted JSON carries [] never null; every OTHER entity leaves these nil,
	// so existing gpo/ou payloads keep their exact shape (custom MarshalJSON
	// below only emits these keys when the field is populated).
	LinkedTo    []EntityGPOLink    `json:"linkedTo,omitempty"`    // gpo → containers it is linked to
	LinkedGpos  []EntityOULink     `json:"linkedGpos,omitempty"`  // ou → gpos linked to it
	Delegations []EntityDelegation `json:"delegations,omitempty"` // gpo permissions / ou delegations
	ChildCounts *EntityChildCounts `json:"childCounts,omitempty"` // ou direct-child census
	WmiFilter   string             `json:"wmiFilter,omitempty"`   // gpo WMI filter (null until gPCWQLFilter is collected)

	// Azure-specific fields (only populated for Azure entities)
	Azure *AzureEntityFields `json:"azure,omitempty"`

	// CertTemplate-specific fields (only populated for certTemplate entities)
	CertTemplate *CertTemplateFields `json:"certTemplate,omitempty"`
}

// EntityGPOLink is one container (Domain/OU/Site) a GPO is linked to, seen from
// the GPO side (T_003). Used by INFO_DOMAIN_GPO_INVENTORY's linkedTo[].
type EntityGPOLink struct {
	DN       string `json:"dn"`
	Scope    string `json:"scope,omitempty"` // "Domain" | "OU" | "Site"
	Enforced bool   `json:"enforced"`
	Enabled  bool   `json:"enabled"`
}

// EntityOULink is one GPO linked to an OU, seen from the OU side (T_003). Used
// by INFO_DOMAIN_OU_INVENTORY's linkedGpos[].
type EntityOULink struct {
	DN       string `json:"dn"`
	Name     string `json:"name,omitempty"`
	Enforced bool   `json:"enforced"`
	Enabled  bool   `json:"enabled"`
	Order    int    `json:"order"`
}

// EntityDelegation is one trustee's aggregated rights on a GPO (rendered as the
// GPO's permissions[]) or on an OU (rendered as the OU's delegations[]) (T_003).
type EntityDelegation struct {
	Trustee string   `json:"trustee"`        // SID
	Name    string   `json:"name,omitempty"` // resolved principal name, when known
	Rights  []string `json:"rights"`
}

// EntityChildCounts is the direct-child object census of an OU (T_003).
type EntityChildCounts struct {
	Users     int `json:"users"`
	Computers int `json:"computers"`
	Groups    int `json:"groups"`
	OUs       int `json:"ous"`
}

// MarshalJSON implements custom JSON marshaling to only include relevant fields per entity type
func (e AffectedEntity) MarshalJSON() ([]byte, error) {
	// If Azure entity, use Azure-specific schema
	if e.Azure != nil {
		switch e.Type {
		case "user":
			return json.Marshal(e.marshalAzureUser())
		case "group":
			return json.Marshal(e.marshalAzureGroup())
		case "application":
			return json.Marshal(e.marshalAzureApplication())
		case "servicePrincipal":
			return json.Marshal(e.marshalAzureServicePrincipal())
		case "conditionalAccessPolicy":
			return json.Marshal(e.marshalAzureConditionalAccessPolicy())
		case "roleAssignment":
			return json.Marshal(e.marshalAzureRoleAssignment())
		case "oauth2Grant":
			return json.Marshal(e.marshalAzureOAuth2Grant())
		default:
			return json.Marshal(e.marshalAzureGeneric())
		}
	}

	// Otherwise, use AD schema
	switch e.Type {
	case "user":
		return json.Marshal(e.marshalUser())
	case "computer":
		return json.Marshal(e.marshalComputer())
	case "group":
		return json.Marshal(e.marshalGroup())
	case "gpo":
		return json.Marshal(e.marshalGPO())
	case "ou":
		return json.Marshal(e.marshalOU())
	case "trust":
		return json.Marshal(e.marshalTrust())
	case "certTemplate":
		return json.Marshal(e.marshalCertTemplate())
	case "domain":
		return json.Marshal(e.marshalDomain())
	case "wellKnownSid":
		return json.Marshal(e.marshalWellKnownSid())
	case "principal":
		return json.Marshal(e.marshalPrincipal())
	case "aclEntry":
		return json.Marshal(e.marshalACLEntry())
	case "dc":
		return json.Marshal(e.marshalDC())
	default:
		// For other types (site, etc.) include minimal fields
		return json.Marshal(e.marshalGeneric())
	}
}

func (e AffectedEntity) marshalUser() map[string]interface{} {
	m := map[string]interface{}{
		"type":           e.Type,
		"dn":             e.DN,
		"sAMAccountName": e.SAMAccountName,
	}
	setIfNotEmpty(m, "userPrincipalName", e.UserPrincipalName)
	setIfNotEmpty(m, "displayName", e.DisplayName)
	setIfNotEmpty(m, "mail", e.Mail)
	setIfNotEmpty(m, "title", e.Title)
	setIfNotEmpty(m, "department", e.Department)
	setIfNotEmpty(m, "company", e.Company)
	setIfNotEmpty(m, "manager", e.Manager)
	setIfNotEmpty(m, "physicalDeliveryOfficeName", e.PhysicalDeliveryOfficeName)
	setIfNotEmpty(m, "description", e.Description)
	setIfNotEmpty(m, "employeeID", e.EmployeeID)
	setIfNotEmpty(m, "telephoneNumber", e.TelephoneNumber)
	setIfNotEmpty(m, "whenCreated", e.WhenCreated)
	setIfNotEmpty(m, "whenChanged", e.WhenChanged)
	// Nullable fields: always include (null if not set)
	m["lastLogon"] = e.LastLogon
	m["pwdLastSet"] = e.PasswordLastSet
	m["accountExpires"] = e.AccountExpires
	m["lockoutTime"] = e.LockoutTime
	m["badPwdCount"] = e.BadPwdCount
	m["adminCount"] = e.AdminCount
	if e.MemberOf != nil {
		m["memberOf"] = e.MemberOf
	} else {
		m["memberOf"] = []string{}
	}
	m["enabled"] = e.Enabled
	return m
}

func (e AffectedEntity) marshalComputer() map[string]interface{} {
	m := map[string]interface{}{
		"type":           e.Type,
		"dn":             e.DN,
		"sAMAccountName": e.SAMAccountName,
	}
	setIfNotEmpty(m, "description", e.Description)
	setIfNotEmpty(m, "dnsHostName", e.DNSHostName)
	setIfNotEmpty(m, "operatingSystem", e.OperatingSystem)
	setIfNotEmpty(m, "operatingSystemVersion", e.OperatingSystemVersion)
	setIfNotEmpty(m, "whenCreated", e.WhenCreated)
	setIfNotEmpty(m, "whenChanged", e.WhenChanged)
	m["lastLogon"] = e.LastLogon
	m["pwdLastSet"] = e.PasswordLastSet
	if e.MemberOf != nil {
		m["memberOf"] = e.MemberOf
	} else {
		m["memberOf"] = []string{}
	}
	m["enabled"] = e.Enabled
	return m
}

func (e AffectedEntity) marshalGroup() map[string]interface{} {
	m := map[string]interface{}{
		"type":           e.Type,
		"dn":             e.DN,
		"sAMAccountName": e.SAMAccountName,
	}
	setIfNotEmpty(m, "name", e.Name)
	setIfNotEmpty(m, "displayName", e.DisplayName)
	setIfNotEmpty(m, "description", e.Description)
	m["memberCount"] = e.MemberCount
	if e.MemberOf != nil {
		m["memberOf"] = e.MemberOf
	} else {
		m["memberOf"] = []string{}
	}
	if e.AdminCount > 0 {
		m["adminCount"] = e.AdminCount
	}
	if len(e.Members) > 0 {
		m["members"] = e.Members
	}
	return m
}

func (e AffectedEntity) marshalGPO() map[string]interface{} {
	m := map[string]interface{}{
		"type": e.Type,
	}
	if e.DN != "" {
		m["dn"] = e.DN
	}
	if e.Name != "" {
		m["name"] = e.Name
	}
	// Eager inventory enrichment (T_003, asset-entities P2 §6). LinkedTo is set
	// (non-nil) only by INFO_DOMAIN_GPO_INVENTORY, so every pre-existing gpo
	// payload (WRITEDACL etc.) keeps its exact {type,dn,name} shape.
	if e.LinkedTo != nil {
		if e.DisplayName != "" {
			m["displayName"] = e.DisplayName
		}
		m["enabled"] = e.Enabled
		m["linkedTo"] = e.LinkedTo // [] never null (detector-initialised)
		m["permissions"] = nonNilDelegations(e.Delegations)
		m["delegations"] = []EntityDelegation{} // GPO delegations fold into permissions[]
		m["wmiFilter"] = nullableString(e.WmiFilter)
		m["blockInheritance"] = false // a GPO never blocks inheritance; key kept for shape stability
	}
	return m
}

// marshalOU renders an organizational-unit entity. It delegates to the generic
// projection so pre-existing ou payloads keep their exact shape, then adds the
// eager inventory keys only when populated by INFO_DOMAIN_OU_INVENTORY (T_003),
// signalled by a non-nil ChildCounts.
func (e AffectedEntity) marshalOU() map[string]interface{} {
	m := e.marshalGeneric()
	if e.ChildCounts != nil {
		m["linkedGpos"] = e.LinkedGpos // [] never null (detector-initialised)
		m["childCounts"] = e.ChildCounts
		m["delegations"] = nonNilDelegations(e.Delegations)
		m["blockInheritance"] = false // gPOptions not threaded yet (follow-up); safe default
	}
	return m
}

// nonNilDelegations guarantees a []EntityDelegation renders as [] not null.
func nonNilDelegations(d []EntityDelegation) []EntityDelegation {
	if d == nil {
		return []EntityDelegation{}
	}
	return d
}

// nullableString renders "" as JSON null (used for optional string fields that
// must be present in the payload but may be unknown, e.g. a GPO's wmiFilter).
func nullableString(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}

func (e AffectedEntity) marshalTrust() map[string]interface{} {
	m := map[string]interface{}{
		"type": e.Type,
	}
	if e.Name != "" {
		m["name"] = e.Name
	}
	return m
}

// marshalDomain emits the v3.1.28 mandatory domain shape: dn, name,
// netbiosName, domainSid, forestRoot, functionalLevel, domainControllerCount.
// Without these fields the SaaS dispatcher cannot tell two domains apart in
// a multi-forest audit.
func (e AffectedEntity) marshalDomain() map[string]interface{} {
	m := map[string]interface{}{
		"type": e.Type,
	}
	if e.DN != "" {
		m["dn"] = e.DN
	}
	if e.Name != "" {
		m["name"] = e.Name
	}
	if e.NetBIOSName != "" {
		m["netbiosName"] = e.NetBIOSName
	}
	if e.DomainSID != "" {
		m["domainSid"] = e.DomainSID
	}
	if e.ForestRoot != "" {
		m["forestRoot"] = e.ForestRoot
	}
	if e.FunctionalLevel != "" {
		m["functionalLevel"] = e.FunctionalLevel
	}
	if e.DomainControllerCount > 0 {
		m["domainControllerCount"] = e.DomainControllerCount
	}
	return m
}

// marshalWellKnownSid emits the v3.1.29 §3 shape: type/sid/name/scope.
// All four fields are mandatory by spec.
func (e AffectedEntity) marshalWellKnownSid() map[string]interface{} {
	return map[string]interface{}{
		"type":  e.Type,
		"sid":   e.SID,
		"name":  e.Name,
		"scope": e.Scope,
	}
}

// marshalPrincipal emits the v3.1.29 §3 shape for unresolved principals:
// type/sid/name/unresolved. The SaaS dispatcher relies on `unresolved=true`
// to render "SID inconnu — orphelin" instead of trying to resolve it as a
// user. name is null (json null) when no name could be obtained.
func (e AffectedEntity) marshalPrincipal() map[string]interface{} {
	m := map[string]interface{}{
		"type":       e.Type,
		"sid":        e.SID,
		"unresolved": e.Unresolved,
	}
	if e.Name != "" {
		m["name"] = e.Name
	} else {
		m["name"] = nil
	}
	// Cache-miss case: when GetUniqueObjectEntities couldn't resolve a DN
	// to a typed entity, we still expose the DN so the SaaS can show
	// something useful instead of just an opaque "unresolved principal".
	if e.DN != "" {
		m["dn"] = e.DN
	}
	return m
}

// marshalACLEntry emits the v3.1.29 §4 shape: trustee/right/target/inheritance.
// All four fields are mandatory and must be non-null per spec.
func (e AffectedEntity) marshalACLEntry() map[string]interface{} {
	m := map[string]interface{}{
		"type":        e.Type,
		"right":       e.Right,
		"inheritance": e.Inheritance,
	}
	if e.Trustee != nil {
		m["trustee"] = e.Trustee
	}
	if e.Target != nil {
		m["target"] = e.Target
	}
	return m
}

// marshalDC emits the v3.1.29 §5 shape. fsmoRoles and replicationPartners
// must always be arrays (never null) per spec — empty slices serialize as [].
func (e AffectedEntity) marshalDC() map[string]interface{} {
	roles := e.FSMORoles
	if roles == nil {
		roles = []string{}
	}
	partners := e.ReplicationPartners
	if partners == nil {
		partners = []string{}
	}
	m := map[string]interface{}{
		"type":                e.Type,
		"dn":                  e.DN,
		"name":                e.Name,
		"dnsHostName":         e.DNSHostName,
		"fsmoRoles":           roles,
		"isReadOnlyDC":        e.IsReadOnlyDC,
		"replicationPartners": partners,
	}
	setIfNotEmpty(m, "operatingSystem", e.OperatingSystem)
	setIfNotEmpty(m, "operatingSystemVersion", e.OperatingSystemVersion)
	setIfNotEmpty(m, "site", e.Site)
	return m
}

func (e AffectedEntity) marshalGeneric() map[string]interface{} {
	m := map[string]interface{}{
		"type": e.Type,
	}
	if e.DN != "" {
		m["dn"] = e.DN
	}
	if e.SAMAccountName != "" {
		m["sAMAccountName"] = e.SAMAccountName
	}
	if e.Name != "" {
		m["name"] = e.Name
	}
	if e.Description != "" {
		m["description"] = e.Description
	}
	return m
}

func (e AffectedEntity) marshalCertTemplate() map[string]interface{} {
	m := map[string]interface{}{
		"type": e.Type,
	}
	if e.DN != "" {
		m["dn"] = e.DN
	}
	if e.SAMAccountName != "" {
		m["sAMAccountName"] = e.SAMAccountName
	}
	if e.Name != "" {
		m["name"] = e.Name
	}
	if e.CertTemplate != nil {
		ct := e.CertTemplate
		setIfNotEmpty(m, "displayName", ct.DisplayName)
		setIfNotEmpty(m, "oid", ct.OID)
		m["schemaVersion"] = ct.SchemaVersion
		m["subjectNameFlag"] = ct.SubjectNameFlag
		m["enrollmentFlag"] = ct.EnrollmentFlag
		m["authorizedSignatures"] = ct.AuthorizedSignatures
		setIfNotEmpty(m, "validityPeriod", ct.ValidityPeriod)
		setIfNotEmpty(m, "renewalPeriod", ct.RenewalPeriod)
		m["enrolleeSuppliesSubject"] = ct.EnrolleeSuppliesSubject
		m["requiresManagerApproval"] = ct.RequiresManagerApproval
		m["clientAuthentication"] = ct.ClientAuthentication
		m["anyPurpose"] = ct.AnyPurpose
		m["enrollmentAgent"] = ct.EnrollmentAgent
		if len(ct.EKUs) > 0 {
			m["ekus"] = ct.EKUs
		}
		if len(ct.EKUNames) > 0 {
			m["ekuNames"] = ct.EKUNames
		}
		setIfNotEmpty(m, "owner", ct.Owner)
		if len(ct.Permissions) > 0 {
			m["permissions"] = ct.Permissions
		}
	}
	return m
}

func setIfNotEmpty(m map[string]interface{}, key, value string) {
	if value != "" {
		m[key] = value
	}
}

// --- Secret redaction in free-text directory attributes (T_031 / B_024) ------
//
// An administrator who writes "pwd=Ete2026!" into an account's description has
// created a credential exposure. The collector must be able to REPORT that
// without SHIPPING it: before T_031, PASSWORD_IN_DESCRIPTION attached the
// verbatim description to its own finding, so the alert that said "there is a
// password in this field" carried the password to the cloud.
//
// The pattern table lives here, next to the entity mappers, so the detector
// that names a match and the mapper that redacts it can never drift apart —
// a redactor that misses what the detector flags is the same bug again.
//
// The model is scanForCPassword (internal/providers/smb/client.go:264-304),
// which proves a GPP cpassword exists by reporting the GPO, the file and the
// finding type — never the value.

// secretPattern is a named indicator that a free-text attribute contains a
// credential. Name is what the report shows instead of the matched text.
type secretPattern struct {
	Name string
	Re   *regexp.Regexp
}

// secretPatterns matches credential-bearing free text. Kept deliberately close
// to the historical PASSWORD_IN_DESCRIPTION patterns so detection is unchanged.
var secretPatterns = []secretPattern{
	{"password-assignment", regexp.MustCompile(`(?i)password\s*[:=]\s*\S+`)},
	{"pwd-assignment", regexp.MustCompile(`(?i)pwd\s*[:=]\s*\S+`)},
	{"pass-assignment", regexp.MustCompile(`(?i)pass\s*[:=]\s*\S+`)},
	{"motdepasse-assignment", regexp.MustCompile(`(?i)motdepasse\s*[:=]\s*\S+`)},
	{"known-weak-password", regexp.MustCompile(`(?i)\bP@ssw0rd\b`)},
	{"known-weak-password", regexp.MustCompile(`(?i)\bPassword123\b`)},
}

// SecretRedactionMarker replaces a matched credential wherever a free-text
// directory attribute is emitted. It states that something was removed and
// why, without reproducing any of it.
const SecretRedactionMarker = "[REDACTED:credential]"

// MatchSecretPatterns returns the distinct names of the patterns that match s,
// in table order. Empty when s carries no credential indicator. Detectors use
// it to report WHICH kind of secret was found without quoting the text.
func MatchSecretPatterns(s string) []string {
	if s == "" {
		return nil
	}
	var names []string
	seen := make(map[string]bool, len(secretPatterns))
	for _, p := range secretPatterns {
		if p.Re.MatchString(s) && !seen[p.Name] {
			seen[p.Name] = true
			names = append(names, p.Name)
		}
	}
	return names
}

// RedactSecrets replaces every credential-looking span in a free-text
// directory attribute with SecretRedactionMarker, leaving the surrounding
// text intact so the entry stays useful for triage ("Service account for
// backups [REDACTED:credential]").
//
// It is applied by every entity mapper below, not just by the detector that
// looks for passwords: a description carrying a secret leaves the host through
// ANY finding that reports that object, so the redaction belongs at the
// choke point rather than in one detector.
func RedactSecrets(s string) string {
	if s == "" {
		return s
	}
	for _, p := range secretPatterns {
		s = p.Re.ReplaceAllString(s, SecretRedactionMarker)
	}
	return s
}

// UserToAffectedEntity converts a User to AffectedEntity with full details (TypeScript-compatible)
func UserToAffectedEntity(u *User) AffectedEntity {
	entity := AffectedEntity{
		Type:                       "user",
		DN:                         u.DN,
		SAMAccountName:             u.SAMAccountName,
		UserPrincipalName:          u.UserPrincipalName,
		DisplayName:                u.DisplayName,
		Mail:                       u.Mail,
		Title:                      u.Title,
		Department:                 u.Department,
		Company:                    u.Company,
		Manager:                    u.Manager,
		PhysicalDeliveryOfficeName: u.PhysicalDeliveryOfficeName,
		Description:                RedactSecrets(u.Description),
		EmployeeID:                 u.EmployeeID,
		TelephoneNumber:            u.TelephoneNumber,
		BadPwdCount:                u.BadPasswordCount,
		MemberOf:                   u.MemberOf,
		Enabled:                    !u.Disabled,
	}

	// Ensure MemberOf is empty array instead of nil for JSON
	if entity.MemberOf == nil {
		entity.MemberOf = []string{}
	}

	// Format timestamps in AD format (YYYYMMDDHHmmss.0Z) like TypeScript
	if !u.Created.IsZero() {
		entity.WhenCreated = u.Created.UTC().Format("20060102150405") + ".0Z"
	}
	if !u.WhenChanged.IsZero() {
		entity.WhenChanged = u.WhenChanged.UTC().Format("20060102150405") + ".0Z"
	}

	// Nullable timestamp fields - use ISO 8601 format like TypeScript
	if !u.LastLogon.IsZero() && u.LastLogon.Year() > 1970 {
		s := u.LastLogon.UTC().Format("2006-01-02T15:04:05.000Z")
		entity.LastLogon = &s
	}
	if !u.PasswordLastSet.IsZero() && u.PasswordLastSet.Year() > 1970 {
		s := u.PasswordLastSet.UTC().Format("2006-01-02T15:04:05.000Z")
		entity.PasswordLastSet = &s
	}
	if !u.AccountExpires.IsZero() && u.AccountExpires.Year() > 1970 && u.AccountExpires.Year() < 9999 {
		s := u.AccountExpires.UTC().Format("2006-01-02T15:04:05.000Z")
		entity.AccountExpires = &s
	}
	if !u.LockoutTime.IsZero() && u.LockoutTime.Year() > 1970 {
		s := u.LockoutTime.UTC().Format("2006-01-02T15:04:05.000Z")
		entity.LockoutTime = &s
	}

	// AdminCount as int (0 or 1)
	if u.AdminCount {
		entity.AdminCount = 1
	}

	// Azure-specific fields (only if present)
	if u.AzureUserType != nil || u.AzureAccountEnabled != nil || u.AzureLastSignInDateTime != nil ||
		u.AzureMfaRegistered != nil || u.AzureJobTitle != nil || u.AzureOfficeLocation != nil ||
		u.AzureCreatedDateTime != nil || u.AzureUsageLocation != nil || len(u.AzureProxyAddresses) > 0 ||
		u.AzureOnPremisesSyncEnabled != nil || len(u.AzureAssignedLicenses) > 0 ||
		u.AzureLastNonInteractiveSignInDateTime != nil || len(u.AzureAuthenticationMethods) > 0 {
		// For Azure users, ObjectSID contains the Azure Object ID, not DN
		if entity.DN == "" && u.ObjectSID != "" {
			entity.DN = u.ObjectSID
		}
		entity.Azure = &AzureEntityFields{
			UserType:                         u.AzureUserType,
			AccountEnabled:                   u.AzureAccountEnabled,
			LastSignInDateTime:               u.AzureLastSignInDateTime,
			LastNonInteractiveSignInDateTime: u.AzureLastNonInteractiveSignInDateTime,
			MfaRegistered:                    u.AzureMfaRegistered,
			JobTitle:                         u.AzureJobTitle,
			OfficeLocation:                   u.AzureOfficeLocation,
			CreatedDateTime:                  u.AzureCreatedDateTime,
			UsageLocation:                    u.AzureUsageLocation,
			ProxyAddresses:                   u.AzureProxyAddresses,
			OnPremisesSyncEnabled:            u.AzureOnPremisesSyncEnabled,
			AssignedLicenses:                 u.AzureAssignedLicenses,
			AuthenticationMethods:            u.AzureAuthenticationMethods,
		}
	}

	return entity
}

// ComputerToAffectedEntity converts a Computer to AffectedEntity with full details
func ComputerToAffectedEntity(c *Computer) AffectedEntity {
	entity := AffectedEntity{
		Type:                   "computer",
		DN:                     c.DN,
		SAMAccountName:         c.SAMAccountName,
		Description:            RedactSecrets(c.Description),
		DNSHostName:            c.DNSHostName,
		OperatingSystem:        c.OperatingSystem,
		OperatingSystemVersion: c.OperatingSystemVersion,
		MemberOf:               c.MemberOf,
		Enabled:                !c.Disabled,
	}

	// Ensure MemberOf is empty array instead of nil for JSON
	if entity.MemberOf == nil {
		entity.MemberOf = []string{}
	}

	// Format timestamps
	if !c.Created.IsZero() {
		entity.WhenCreated = c.Created.UTC().Format("20060102150405") + ".0Z"
	}
	if !c.WhenChanged.IsZero() {
		entity.WhenChanged = c.WhenChanged.UTC().Format("20060102150405") + ".0Z"
	}
	if !c.LastLogon.IsZero() && c.LastLogon.Year() > 1970 {
		s := c.LastLogon.UTC().Format("2006-01-02T15:04:05.000Z")
		entity.LastLogon = &s
	}
	if !c.PasswordLastSet.IsZero() && c.PasswordLastSet.Year() > 1970 {
		s := c.PasswordLastSet.UTC().Format("2006-01-02T15:04:05.000Z")
		entity.PasswordLastSet = &s
	}

	return entity
}

// GroupToAffectedEntity converts a Group to AffectedEntity with full details
func GroupToAffectedEntity(g *Group) AffectedEntity {
	// Determine the best name to use
	name := g.DisplayName
	if name == "" {
		name = g.CN
	}
	if name == "" {
		name = g.SAMAccountName
	}

	// Member count from Members or Member (alias)
	memberCount := len(g.Members)
	if memberCount == 0 {
		memberCount = len(g.Member)
	}

	// Prefer Members, fall back to Member (raw LDAP alias).
	memberList := g.Members
	if len(memberList) == 0 {
		memberList = g.Member
	}

	entity := AffectedEntity{
		Type:           "group",
		DN:             g.DN,
		SAMAccountName: g.SAMAccountName,
		Name:           name,
		DisplayName:    g.DisplayName,
		Description:    RedactSecrets(g.Description),
		MemberOf:       g.MemberOf,
		MemberCount:    memberCount,
		Members:        memberList,
	}

	// Ensure MemberOf is empty array instead of nil for JSON
	if entity.MemberOf == nil {
		entity.MemberOf = []string{}
	}

	// AdminCount as int (0 or 1)
	if g.AdminCount {
		entity.AdminCount = 1
	}

	// Azure-specific fields (only if present)
	if len(g.AzureGroupTypes) > 0 || g.AzureSecurityEnabled != nil || g.AzureMailEnabled != nil ||
		g.AzureMembershipRule != nil || g.AzureMembershipRuleProcessingState != nil ||
		g.AzureIsAssignableToRole != nil || g.AzureVisibility != nil || g.AzureCreatedDateTime != nil ||
		g.AzureOnPremisesSyncEnabled != nil || g.AzureExternalMembersCount != nil {
		// For Azure groups, ObjectSID contains the Azure Object ID, not DN
		if entity.DN == "" && g.ObjectSID != "" {
			entity.DN = g.ObjectSID
		}
		entity.Azure = &AzureEntityFields{
			GroupTypes:                    g.AzureGroupTypes,
			SecurityEnabled:               g.AzureSecurityEnabled,
			MailEnabled:                   g.AzureMailEnabled,
			MembershipRule:                g.AzureMembershipRule,
			MembershipRuleProcessingState: g.AzureMembershipRuleProcessingState,
			IsAssignableToRole:            g.AzureIsAssignableToRole,
			Visibility:                    g.AzureVisibility,
			CreatedDateTime:               g.AzureCreatedDateTime,
			GroupOnPremisesSyncEnabled:    g.AzureOnPremisesSyncEnabled,
			ExternalMembersCount:          g.AzureExternalMembersCount,
		}
	}

	return entity
}

// GPOToAffectedEntity converts a GPO to AffectedEntity
func GPOToAffectedEntity(g *GPO) AffectedEntity {
	name := g.DisplayName
	if name == "" {
		name = g.CN
	}
	return AffectedEntity{
		Type: "gpo",
		DN:   g.DN,
		Name: name,
	}
}

// DomainInfoToAffectedEntity converts a DomainInfo to a typed domain
// AffectedEntity. Used by the 9 detectors that previously emitted bare
// {Type: "domain"} entries with no identifying fields. The SaaS dispatcher
// needs dn/name/netbiosName/domainSid/forestRoot to distinguish multiple
// domains in a multi-forest audit.
func DomainInfoToAffectedEntity(d *DomainInfo) AffectedEntity {
	if d == nil {
		return AffectedEntity{Type: EntityTypeDomain}
	}
	dn := d.DomainDN
	if dn == "" {
		dn = d.DN
	}
	return AffectedEntity{
		Type:                  EntityTypeDomain,
		DN:                    dn,
		Name:                  d.DomainName,
		NetBIOSName:           d.NetBIOSName,
		DomainSID:             d.DomainSID,
		ForestRoot:            d.ForestName,
		FunctionalLevel:       d.FunctionalLevel,
		DomainControllerCount: len(d.DomainControllers),
	}
}

// TrustToAffectedEntity converts a Trust to AffectedEntity
func TrustToAffectedEntity(t *Trust) AffectedEntity {
	name := t.Name
	if name == "" {
		name = t.TargetDomain
	}
	return AffectedEntity{
		Type: "trust",
		Name: name,
	}
}

// CertTemplateToAffectedEntity converts a CertTemplate to AffectedEntity with full ADCS attributes
func CertTemplateToAffectedEntity(t *CertTemplate) AffectedEntity {
	name := t.Name
	if name == "" {
		name = t.DisplayName
	}

	// Derive boolean flags from raw fields (OID literals to avoid circular import with adcs package)
	enrolleeSuppliesSubject := (t.SubjectNameFlag & 0x00000001) != 0 // CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT
	requiresManagerApproval := (t.EnrollmentFlag & 0x00000002) != 0  // CT_FLAG_PEND_ALL_REQUESTS

	var clientAuth, anyPurpose, enrollmentAgent bool
	for _, eku := range t.ExtendedKeyUsage {
		switch eku {
		case "1.3.6.1.5.5.7.3.2", "1.3.6.1.4.1.311.20.2.2", "1.3.6.1.5.2.3.4":
			clientAuth = true
		case "2.5.29.37.0":
			anyPurpose = true
		case "1.3.6.1.4.1.311.20.2.1":
			enrollmentAgent = true
		}
	}

	return AffectedEntity{
		Type:           "certTemplate",
		DN:             t.DN,
		SAMAccountName: name,
		Name:           name,
		CertTemplate: &CertTemplateFields{
			DisplayName:             t.DisplayName,
			OID:                     t.OID,
			SchemaVersion:           t.SchemaVersion,
			SubjectNameFlag:         t.SubjectNameFlag,
			EnrollmentFlag:          t.EnrollmentFlag,
			AuthorizedSignatures:    t.AuthorizedSignatures,
			ValidityPeriod:          t.ValidityPeriod,
			RenewalPeriod:           t.RenewalPeriod,
			EnrolleeSuppliesSubject: enrolleeSuppliesSubject,
			RequiresManagerApproval: requiresManagerApproval,
			ClientAuthentication:    clientAuth,
			AnyPurpose:              anyPurpose,
			EnrollmentAgent:         enrollmentAgent,
			EKUs:                    t.ExtendedKeyUsage,
			EKUNames:                ResolveEKUNames(t.ExtendedKeyUsage),
		},
	}
}

// RoleAssignmentToAffectedEntity converts an Azure role assignment to an affected entity
func RoleAssignmentToAffectedEntity(ra *RoleAssignment) AffectedEntity {
	return AffectedEntity{
		Type:        "roleAssignment",
		DN:          ra.PrincipalID, // Use PrincipalID as unique identifier
		DisplayName: ra.PrincipalName,
		Azure: &AzureEntityFields{
			RoleName:              &ra.RoleName,
			PrincipalType:         &ra.PrincipalType,
			IsPermanent:           &ra.IsPermanent,
			AssignmentScope:       &ra.DirectoryScopeID,
			AssignmentType:        &ra.AssignmentType,
			MemberType:            &ra.MemberType,
			ActivationDuration:    &ra.ActivationDuration,
			Justification:         &ra.Justification,
			TicketInfo:            &ra.TicketInfo,
			IsEligible:            &ra.IsEligible,
			RequiresJustification: &ra.RequiresJustification,
			RequiresApproval:      &ra.RequiresApproval,
		},
	}
}

// FindingSummary is a compact representation of a finding
type FindingSummary struct {
	Type     string   `json:"type"`
	Severity Severity `json:"severity"`
	Count    int      `json:"count"`
}

// AuditResult represents the result of an audit
type AuditResult struct {
	Timestamp    time.Time          `json:"timestamp"`
	Duration     time.Duration      `json:"duration"`
	Score        float64            `json:"score"`
	Rating       string             `json:"rating"`
	ScoreDetails *ScoreDetails      `json:"scoreDetails,omitempty"`
	Provider     string             `json:"provider"`
	Domain       string             `json:"domain,omitempty"`
	DomainInfo   *DomainInfo        `json:"domainInfo,omitempty"` // Domain configuration and policies
	Findings     []Finding          `json:"findings"`
	Statistics   *AuditStatistics   `json:"statistics"`
	Summary      []FindingSummary   `json:"summary,omitempty"`
	Warnings     []Warning          `json:"warnings,omitempty"`
	AttackGraph  *AttackGraphExport `json:"attackGraph,omitempty"`
	// Exclusions describes any asset-level or detector-level filters that were
	// applied to this run, and how many objects each rule matched. Enables
	// external auditors to reproduce / compare / contest a score.
	Exclusions *ExclusionReport `json:"exclusions,omitempty"`
	// ComplianceScores is populated by audit/compliance.CalculatePerFramework
	// and forwarded to AuditReport.Summary.ComplianceScores by ConvertToTSFormat.
	ComplianceScores []FrameworkScore `json:"-"`

	// v3.1.30 §1 — Azure sign-in logs deep collection. Populated by
	// engine.collectAzureData and forwarded to AuditResponse by
	// ConvertToTSFormat. SignInLogs is set when mode=raw, SignInLogsAggregated
	// when mode=aggregated. Truncated/EventsCollected/OldestCollected are
	// surfaced regardless so the SaaS knows the real lookback window.
	SignInLogs                []SignInLog           `json:"signInLogs,omitempty"`
	SignInLogsAggregated      *SignInLogsAggregated `json:"signInLogsAggregated,omitempty"`
	SignInLogsTruncated       bool                  `json:"signInLogsTruncated,omitempty"`
	SignInLogsEventsCollected int                   `json:"signInLogsEventsCollected,omitempty"`
	SignInLogsOldestCollected *time.Time            `json:"signInLogsOldestCollected,omitempty"`
	SignInLogsRequestedDays   int                   `json:"signInLogsRequestedDays,omitempty"`
	SignInLogsActualDays      int                   `json:"signInLogsActualDays,omitempty"`

	// v3.1.30 §3 — Azure OAuth grants + service principals (ConsentFix
	// detection input). OAuthGrants exposes the enriched grants list with
	// dangerousScopes flagged. ServicePrincipals exposes the per-SP detail
	// (signInAudience, tags, verifiedPublisher, owners, appRoleAssignments,
	// credentials) for the SaaS analyzer.
	OAuthGrants       *OAuthGrantsSummary `json:"oauthGrants,omitempty"`
	ServicePrincipals []ServicePrincipal  `json:"servicePrincipals,omitempty"`

	// v3.1.30 §4 — PIM (Privileged Identity Management) detail.
	// PIMAssignments groups active + eligible + neverActivated for the
	// drift timeline. PIMActivationHistory carries the 90-day request
	// log with justifications and ticket refs.
	PIMAssignments       *PIMAssignmentsSummary       `json:"pimAssignments,omitempty"`
	PIMActivationHistory *PIMActivationHistorySummary `json:"pimActivationHistory,omitempty"`

	// v3.1.30 §5 — Cross-tenant access policy detail. Default + per-partner
	// + multi-tenant-org config. Powers the SaaS partner-trust map.
	CrossTenantAccess *CrossTenantAccessSummary `json:"crossTenantAccess,omitempty"`

	// v3.1.30 §6 — Auth methods policy + strength policies + per-user
	// adoption stats. Powers the SaaS Authentication Method Coverage donut
	// and admin auth-strength enforcement check.
	AuthenticationMethodsDetail *AuthMethodsDetail `json:"authenticationMethodsDetail,omitempty"`

	// v3.1.30 §7 — App registrations (top-level slice, mirrors §3 SPs) +
	// tenant-wide credential expiry rollup (per-app + per-SP buckets).
	// Per-credential CredentialStatus and per-entity CredentialSummary live
	// on each AppRegistration / ServicePrincipal already. Powers the SaaS
	// "Credential Expiration Cliff" widget and urgency-sorted findings.
	Applications     []AppRegistration        `json:"applications,omitempty"`
	CredentialExpiry *CredentialExpirySummary `json:"credentialExpiry,omitempty"`

	// v3.1.36 — Directory audit logs (90 days, 5 security categories:
	// RoleManagement, ConditionalAccess, ApplicationManagement,
	// GroupManagement, UserManagement). Powers the SaaS Identity Drift
	// Timeline + diff-vs-previous-audit + auditor evidence flows.
	DirectoryAudits *DirectoryAuditsSummary `json:"directoryAudits,omitempty"`

	// v3.1.37 §1 — Microsoft Baseline Security Mode adoption rollup.
	// 20 hardcoded policy checks derived from already-collected data
	// (SecurityDefaults, CA policies, AuthMethodsDetail.Policy,
	// AuthorizationPolicy). Powers the SaaS Executive Tab "Baseline
	// Adoption" widget (KPI #20).
	BaselineSecurity *BaselineSecuritySummary `json:"baselineSecurity,omitempty"`

	// v3.1.37 §2 — Microsoft Entra Backup & Recovery status. Probed via
	// a single Graph call that today returns Available=false (API not yet
	// GA at the time of this collector); will surface real config when
	// Microsoft ships the endpoint. Powers KPI #21.
	EntraBackup *EntraBackupStatus `json:"entraBackup,omitempty"`

	// v3.1.37 §3 — AI agent role assignments rollup (Silverfort Mar 2026
	// advisory on Agent ID Administrator scope flaw). Filters Entra roles
	// by name prefix (Agent / AI / Copilot / Knowledge), expands Group
	// principals to count actual humans. Powers KPI #26.
	AIAgentRoles *AIAgentRolesSummary `json:"aiAgentRoles,omitempty"`

	// v3.1.38 §1 — License ROI matrix. Subscribed SKUs + per-feature
	// utilization (PIM / Identity Protection / Conditional Access /
	// Access Reviews / Entitlement Management / Verified ID) +
	// P2 user-activity distribution. Powers KPI #12.
	LicenseInfo *LicenseInfoSummary `json:"licenseInfo,omitempty"`

	// v3.1.38 §2 — Hybrid edges Entra ↔ AD. Sync stats + per-user
	// onPremises identifiers + HAJ devices + federated trust risks.
	// Powers KPI #17 (Hybrid Attack Paths Visualizer).
	HybridLinks *HybridLinksSummary `json:"hybridLinks,omitempty"`

	// v3.1.38 §3 — Conditional Access policies (full nested Microsoft Graph
	// shape). Lets the SaaS analyzer compute per-control adoption %
	// (Token Protection, Sign-in Frequency, Persistent Browser,
	// Authentication Strength, ...). Powers KPI #22 (Token Protection
	// adoption %) and KPI #14 (CA coverage matrix).
	ConditionalAccessPolicies []ConditionalAccessPolicyDetail `json:"conditionalAccessPolicies,omitempty"`

	// v3.1.39 §1 — Continuous Access Evaluation tenant rollup. Adoption
	// %, modesByPolicy, resilience-defaults bypass list, and per-app
	// coverage flags for Office365/Exchange/SharePoint/Teams. Powers
	// KPI #23.
	CAE *CAESummary `json:"cae,omitempty"`

	// v3.1.39 §2 — Bookings / first-party orphan accounts rollup.
	// Cloud-only users matching creationType ∈ {Resource,EmailVerified,
	// EmailUnverified} OR UPN regex (bookings*, forms*, svc-, app-, ...).
	// Powers KPI #25.
	FirstPartyAccounts *FirstPartyAccountsSummary `json:"firstPartyAccounts,omitempty"`

	// v3.1.39 §3 — MFA registration CA policy rollup. Filters CA policies
	// targeting userActions = urn:user:registersecurityinfo and tells the
	// SaaS analyzer whether enrollment is restricted to trusted locations.
	// Powers KPI #27.
	MFARegistrationPolicy *MFARegistrationPolicySummary `json:"mfaRegistrationPolicy,omitempty"`
}

// ExclusionReport is the serialisable summary of asset + detector exclusions
// applied during an audit. Mirror of internal/audit/exclusions.Report without
// the import coupling.
type ExclusionReport struct {
	RulesHash    string                      `json:"rulesHash,omitempty"`
	RulesVersion int                         `json:"rulesVersion"`
	AssetCounts  map[string]*ExclusionCounts `json:"assetCounts,omitempty"` // key: "users" | "computers" | "groups" | "ous"
	PerDetector  []ExclusionPerDetector      `json:"perDetector,omitempty"`
}

// ExclusionCounts holds the total / scanned / excluded breakdown for an asset
// type plus the list of match reasons.
type ExclusionCounts struct {
	Total    int               `json:"total"`
	Scanned  int               `json:"scanned"`
	Excluded int               `json:"excluded"`
	Reasons  []ExclusionReason `json:"reasons,omitempty"`
}

// ExclusionReason is a per-rule hit count with up to a few sample DNs.
type ExclusionReason struct {
	Field     string   `json:"field"`   // "dn" | "under_ou" | "sam" | "hostname" | "name" | "regex" | "scope" | "include"
	Pattern   string   `json:"pattern"` // raw rule text
	Matched   int      `json:"matched"`
	SampleDNs []string `json:"sampleDNs,omitempty"` // up to 5
}

// ExclusionPerDetector records that detectorID was not evaluated on `Matched`
// objects under the given asset scope.
type ExclusionPerDetector struct {
	DetectorID string   `json:"detectorId"`
	Reason     string   `json:"reason,omitempty"`
	Scope      string   `json:"scope"` // "users" | "computers" | "groups" | "ous"
	Matched    int      `json:"matched"`
	SampleDNs  []string `json:"sampleDNs,omitempty"`
}

// AuditStatistics contains statistical information about an audit
type AuditStatistics struct {
	TotalFindings    int              `json:"totalFindings"`
	BySeverity       map[Severity]int `json:"bySeverity"`
	ByCategory       map[string]int   `json:"byCategory"`
	UsersScanned     int              `json:"usersScanned"`
	GroupsScanned    int              `json:"groupsScanned"`
	ComputersScanned int              `json:"computersScanned"`
	OUsScanned       int              `json:"ousScanned"`
	// UsersDisabled / UsersEnabled are the real split of UsersScanned (T_031).
	// The report summary used to hard-code users_disabled to 0 and
	// users_enabled to the full scanned count, which on DC01 announced
	// "0 disabled" for a domain where 519 of 546 accounts are disabled.
	UsersDisabled int `json:"usersDisabled"`
	UsersEnabled  int `json:"usersEnabled"`
	// Azure-specific counts (populated only for Azure audits)
	GuestUsers                int    `json:"guestUsers,omitempty"`
	Applications              int    `json:"applications,omitempty"`
	ServicePrincipals         int    `json:"servicePrincipals,omitempty"`
	ConditionalAccessPolicies int    `json:"conditionalAccessPolicies,omitempty"`
	CAPoliciesEnabled         int    `json:"caPoliciesEnabled,omitempty"`
	CAPoliciesDisabled        int    `json:"caPoliciesDisabled,omitempty"`
	PIMEnabled                bool   `json:"pimEnabled,omitempty"`
	PIMEligibleRoles          int    `json:"pimEligibleRoles,omitempty"`
	IdentityProtectionEnabled bool   `json:"identityProtectionEnabled,omitempty"`
	RiskyUsersCount           *int   `json:"riskyUsersCount,omitempty"`
	RiskySignInsCount         *int   `json:"riskySignInsCount,omitempty"`
	MFAEnforcedUsers          int    `json:"mfaEnforcedUsers,omitempty"`
	MFACapableUsers           int    `json:"mfaCapableUsers,omitempty"`
	MFANotConfiguredUsers     int    `json:"mfaNotConfiguredUsers,omitempty"`
	LicenseType               string `json:"licenseType,omitempty"`
	TenantDomain              string `json:"tenantDomain,omitempty"`
}

// NewAuditStatistics creates a new AuditStatistics with initialized maps
func NewAuditStatistics() *AuditStatistics {
	return &AuditStatistics{
		BySeverity: make(map[Severity]int),
		ByCategory: make(map[string]int),
	}
}

// ScoreDetails contains the entity-type weighted scoring breakdown
type ScoreDetails struct {
	WeightedByType      map[string]float64 `json:"weightedByType"`
	AdjustedWeighted    float64            `json:"adjustedWeighted"`
	AdjustedDenominator float64            `json:"adjustedDenominator"`
}

// categoryEntityWeight returns the entity-type weight for a finding category.
// Users (1.0) > Computers (0.5) > Groups (0.2) > ACL entries (0.1).
func categoryEntityWeight(category string) float64 {
	switch category {
	case "computers", "network":
		return 0.5
	case "permissions":
		return 0.1
	default: // password, accounts, kerberos, groups, gpo, trusts, adcs, attack-paths, monitoring, compliance, advanced, config
		return 1.0
	}
}

// entityTypeKey returns the entity type label for a finding category.
func entityTypeKey(category string) string {
	switch category {
	case "computers", "network":
		return "computer"
	case "permissions":
		return "acl"
	default:
		return "user"
	}
}

// CalculateScore calculates the security score using entity-type weighted logarithmic scale.
// Each finding's weighted value is multiplied by an entity-type weight based on its category.
// The denominator combines totalUsers, totalComputers, and totalGroups with the same weights.
// Score is 0-100 (100 = perfect), rounded to 1 decimal place.
func CalculateScore(findings []Finding, totalUsers, totalComputers, totalGroups int) (float64, *ScoreDetails) {
	if len(findings) == 0 {
		return 100.0, &ScoreDetails{
			WeightedByType: map[string]float64{"user": 0, "computer": 0, "acl": 0},
		}
	}

	// Accumulate severity-weighted counts by entity type
	weightedByType := map[string]float64{"user": 0, "computer": 0, "acl": 0}
	for _, f := range findings {
		sevWeight := f.Severity.Weight()
		if sevWeight == 0 {
			continue
		}
		entityWeight := categoryEntityWeight(f.Category)
		key := entityTypeKey(f.Category)
		weightedByType[key] += float64(f.Count) * sevWeight * entityWeight
	}

	// Adjusted numerator
	adjustedWeighted := weightedByType["user"] + weightedByType["computer"] + weightedByType["acl"]

	// Adjusted denominator: totalUsers×1.0 + totalComputers×0.5 + totalGroups×0.2
	adjustedDenominator := float64(totalUsers)*1.0 + float64(totalComputers)*0.5 + float64(totalGroups)*0.2
	if adjustedDenominator < 1 {
		adjustedDenominator = 1
	}

	ratio := adjustedWeighted / adjustedDenominator

	// Logarithmic dampening
	normalizedRatio := math.Log10(ratio+1) * 50

	score := 100.0 - normalizedRatio
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}

	// Round to 1 decimal place
	score = math.Round(score*10) / 10

	details := &ScoreDetails{
		WeightedByType:      weightedByType,
		AdjustedWeighted:    math.Round(adjustedWeighted*10) / 10,
		AdjustedDenominator: math.Round(adjustedDenominator*10) / 10,
	}

	return score, details
}

// CalculateRating returns a rating string based on score (matches backend)
func CalculateRating(score float64) string {
	switch {
	case score >= 70:
		return "low"
	case score >= 50:
		return "medium"
	case score >= 25:
		return "high"
	default:
		return "critical"
	}
}

// ===== Azure-specific marshalling functions =====

func (e AffectedEntity) marshalAzureUser() map[string]interface{} {
	m := map[string]interface{}{
		"id":                e.DN, // DN contains Azure Object ID
		"userPrincipalName": e.UserPrincipalName,
	}
	mergeSignInRiskContext(m, e.Azure)
	if len(e.Azure.SignInRiskContext) > 0 {
		m["type"] = e.Type
	}
	setIfNotEmpty(m, "displayName", e.DisplayName)
	setIfNotEmpty(m, "mail", e.Mail)

	// Azure-specific fields from entity.Azure
	if e.Azure.UserType != nil {
		m["userType"] = *e.Azure.UserType
	}
	if e.Azure.AccountEnabled != nil {
		m["accountEnabled"] = *e.Azure.AccountEnabled
	}
	if e.Azure.LastSignInDateTime != nil {
		m["lastSignInDateTime"] = e.Azure.LastSignInDateTime.UTC().Format("2006-01-02T15:04:05Z")
	}
	if e.Azure.MfaRegistered != nil {
		m["mfaRegistered"] = *e.Azure.MfaRegistered
	}
	if e.Azure.RiskLevel != nil {
		m["riskLevel"] = *e.Azure.RiskLevel
	}
	if e.Azure.RiskState != nil {
		m["riskState"] = *e.Azure.RiskState
	}
	if e.Azure.JobTitle != nil {
		setIfNotEmpty(m, "jobTitle", *e.Azure.JobTitle)
	}
	setIfNotEmpty(m, "department", e.Department)
	if e.Azure.OfficeLocation != nil {
		setIfNotEmpty(m, "officeLocation", *e.Azure.OfficeLocation)
	}
	if e.Azure.CreatedDateTime != nil {
		m["createdDateTime"] = e.Azure.CreatedDateTime.UTC().Format("2006-01-02T15:04:05Z")
	}
	if e.Azure.LastNonInteractiveSignInDateTime != nil {
		m["lastNonInteractiveSignInDateTime"] = e.Azure.LastNonInteractiveSignInDateTime.UTC().Format("2006-01-02T15:04:05Z")
	}
	if e.Azure.UsageLocation != nil {
		m["usageLocation"] = *e.Azure.UsageLocation
	}
	if len(e.Azure.ProxyAddresses) > 0 {
		m["proxyAddresses"] = e.Azure.ProxyAddresses
	}
	if e.Azure.OnPremisesSyncEnabled != nil {
		m["onPremisesSyncEnabled"] = *e.Azure.OnPremisesSyncEnabled
	}
	if len(e.Azure.AssignedLicenses) > 0 {
		m["assignedLicenses"] = e.Azure.AssignedLicenses
	}
	if len(e.Azure.AuthenticationMethods) > 0 {
		m["authenticationMethods"] = e.Azure.AuthenticationMethods
	}

	return m
}

func (e AffectedEntity) marshalAzureGroup() map[string]interface{} {
	m := map[string]interface{}{
		"id":          e.DN, // DN contains Azure Object ID
		"displayName": e.DisplayName,
	}
	setIfNotEmpty(m, "description", e.Description)
	m["memberCount"] = e.MemberCount

	// Azure-specific fields
	if len(e.Azure.GroupTypes) > 0 {
		m["groupTypes"] = e.Azure.GroupTypes
	} else {
		m["groupTypes"] = []string{}
	}
	if e.Azure.SecurityEnabled != nil {
		m["securityEnabled"] = *e.Azure.SecurityEnabled
	}
	if e.Azure.MailEnabled != nil {
		m["mailEnabled"] = *e.Azure.MailEnabled
	}
	if e.Azure.MembershipRuleProcessingState != nil {
		m["membershipRuleProcessingState"] = *e.Azure.MembershipRuleProcessingState
	}
	if e.Azure.IsAssignableToRole != nil {
		m["isAssignableToRole"] = *e.Azure.IsAssignableToRole
	}
	if e.Azure.OwnerCount != nil {
		m["ownerCount"] = *e.Azure.OwnerCount
	}
	if e.Azure.Visibility != nil {
		m["visibility"] = *e.Azure.Visibility
	}
	if e.Azure.MembershipRule != nil {
		setIfNotEmpty(m, "membershipRule", *e.Azure.MembershipRule)
	}
	if e.Azure.CreatedDateTime != nil {
		m["createdDateTime"] = e.Azure.CreatedDateTime.UTC().Format("2006-01-02T15:04:05Z")
	}
	if e.Azure.GroupOnPremisesSyncEnabled != nil {
		m["onPremisesSyncEnabled"] = *e.Azure.GroupOnPremisesSyncEnabled
	}
	if e.Azure.ExternalMembersCount != nil {
		m["externalMembersCount"] = *e.Azure.ExternalMembersCount
	}
	if len(e.Members) > 0 {
		m["members"] = e.Members
	}

	return m
}

func (e AffectedEntity) marshalAzureApplication() map[string]interface{} {
	m := map[string]interface{}{
		"id":          e.DN, // DN contains Azure Object ID
		"displayName": e.DisplayName,
	}

	// Azure-specific fields
	if e.Azure.AppId != nil {
		m["appId"] = *e.Azure.AppId
	}
	if e.Azure.SignInAudience != nil {
		m["signInAudience"] = *e.Azure.SignInAudience
	}
	if e.Azure.CreatedDateTime != nil {
		m["createdDateTime"] = e.Azure.CreatedDateTime.UTC().Format("2006-01-02T15:04:05Z")
	}
	if e.Azure.AppLastSignInDateTime != nil {
		m["appLastSignInDateTime"] = e.Azure.AppLastSignInDateTime.UTC().Format("2006-01-02T15:04:05Z")
	}
	if len(e.Azure.Owners) > 0 {
		m["owners"] = e.Azure.Owners
	}
	if e.Azure.AppOwnerCount != nil {
		m["appOwnerCount"] = *e.Azure.AppOwnerCount
	}
	if e.Azure.HasExpiredCredentials != nil {
		m["hasExpiredCredentials"] = *e.Azure.HasExpiredCredentials
	}
	if e.Azure.CredentialExpiryDate != nil {
		m["credentialExpiryDate"] = e.Azure.CredentialExpiryDate.UTC().Format("2006-01-02T15:04:05Z")
	}
	if len(e.Azure.DangerousPermissions) > 0 {
		m["dangerousPermissions"] = e.Azure.DangerousPermissions
	}
	if len(e.Azure.ApiPermissions) > 0 {
		m["apiPermissions"] = e.Azure.ApiPermissions
	}
	if e.Azure.ImplicitGrantEnabled != nil {
		m["implicitGrantEnabled"] = *e.Azure.ImplicitGrantEnabled
	}
	if e.Azure.CredentialCount != nil {
		m["credentialCount"] = *e.Azure.CredentialCount
	}
	if e.Azure.PublisherDomain != nil {
		setIfNotEmpty(m, "publisherDomain", *e.Azure.PublisherDomain)
	}
	if e.Azure.Homepage != nil {
		setIfNotEmpty(m, "homepage", *e.Azure.Homepage)
	}
	if e.Azure.LogoutUrl != nil {
		setIfNotEmpty(m, "logoutUrl", *e.Azure.LogoutUrl)
	}

	// Build description
	audience := ""
	if e.Azure.SignInAudience != nil {
		audience = *e.Azure.SignInAudience
	}
	appId := ""
	if e.Azure.AppId != nil {
		appId = *e.Azure.AppId
	}
	m["description"] = fmt.Sprintf("AppID: %s, Audience: %s", appId, audience)

	return m
}

func (e AffectedEntity) marshalAzureServicePrincipal() map[string]interface{} {
	m := map[string]interface{}{
		"id":          e.DN, // DN contains Azure Object ID
		"displayName": e.DisplayName,
	}
	m["accountEnabled"] = e.Enabled

	// Azure-specific fields
	if e.Azure.ServicePrincipalType != nil {
		m["servicePrincipalType"] = *e.Azure.ServicePrincipalType
	}
	if e.Azure.AppId != nil {
		m["appId"] = *e.Azure.AppId
	}
	if e.Azure.IsFirstParty != nil {
		m["isFirstParty"] = *e.Azure.IsFirstParty
	}
	if e.Azure.CreatedDateTime != nil {
		m["createdDateTime"] = e.Azure.CreatedDateTime.UTC().Format("2006-01-02T15:04:05Z")
	}
	if e.Azure.AppLastSignInDateTime != nil {
		m["appLastSignInDateTime"] = e.Azure.AppLastSignInDateTime.UTC().Format("2006-01-02T15:04:05Z")
	}
	if len(e.Azure.Owners) > 0 {
		m["owners"] = e.Azure.Owners
	}
	if e.Azure.AppOwnerCount != nil {
		m["ownerCount"] = *e.Azure.AppOwnerCount
	}
	if e.Azure.AppRoleAssignmentsCount != nil {
		m["appRoleAssignmentsCount"] = *e.Azure.AppRoleAssignmentsCount
	}
	if e.Azure.HasExpiredCredentials != nil {
		m["hasExpiredCredentials"] = *e.Azure.HasExpiredCredentials
	}
	if e.Azure.CredentialExpiryDate != nil {
		m["credentialExpiryDate"] = e.Azure.CredentialExpiryDate.UTC().Format("2006-01-02T15:04:05Z")
	}
	if e.Azure.CredentialCount != nil {
		m["credentialCount"] = *e.Azure.CredentialCount
	}
	if e.Azure.AppOwnerOrganizationId != nil {
		setIfNotEmpty(m, "appOwnerOrganizationId", *e.Azure.AppOwnerOrganizationId)
	}
	if e.Azure.AppRoleAssignmentRequired != nil {
		m["appRoleAssignmentRequired"] = *e.Azure.AppRoleAssignmentRequired
	}

	// Build description
	spType := ""
	if e.Azure.ServicePrincipalType != nil {
		spType = *e.Azure.ServicePrincipalType
	}
	appId := ""
	if e.Azure.AppId != nil {
		appId = *e.Azure.AppId
	}
	m["description"] = fmt.Sprintf("Type: %s, AppID: %s", spType, appId)

	return m
}

func (e AffectedEntity) marshalAzureConditionalAccessPolicy() map[string]interface{} {
	m := map[string]interface{}{
		"id":          e.DN, // DN contains Azure Object ID
		"displayName": e.DisplayName,
	}
	setIfNotEmpty(m, "description", e.Description)

	// Azure-specific fields
	if e.Azure.State != nil {
		m["state"] = *e.Azure.State
	}
	if e.Azure.Conditions != nil {
		m["conditions"] = *e.Azure.Conditions
	}
	if len(e.Azure.GrantControls) > 0 {
		m["grantControls"] = e.Azure.GrantControls
	}
	if len(e.Azure.UserRiskLevels) > 0 {
		m["userRiskLevels"] = e.Azure.UserRiskLevels
	}
	if len(e.Azure.SignInRiskLevels) > 0 {
		m["signInRiskLevels"] = e.Azure.SignInRiskLevels
	}
	if len(e.Azure.IncludeUsers) > 0 {
		m["includeUsers"] = e.Azure.IncludeUsers
	}
	if len(e.Azure.ExcludeUsers) > 0 {
		m["excludeUsers"] = e.Azure.ExcludeUsers
	}
	if len(e.Azure.IncludeApps) > 0 {
		m["includeApps"] = e.Azure.IncludeApps
	}

	return m
}

func (e AffectedEntity) marshalAzureRoleAssignment() map[string]interface{} {
	m := map[string]interface{}{
		"id": e.DN, // DN contains principal ID (Azure Object ID)
	}
	setIfNotEmpty(m, "displayName", e.DisplayName)
	setIfNotEmpty(m, "description", e.Description)

	// Role fields
	if e.Azure.RoleName != nil {
		m["roleName"] = *e.Azure.RoleName
	}
	if e.Azure.RoleDefinitionId != nil {
		setIfNotEmpty(m, "roleDefinitionId", *e.Azure.RoleDefinitionId)
	}
	// Principal identity fields
	if e.Azure.PrincipalType != nil {
		m["principalType"] = *e.Azure.PrincipalType
	}
	if e.Azure.PrincipalUpn != nil {
		setIfNotEmpty(m, "principalUpn", *e.Azure.PrincipalUpn)
		setIfNotEmpty(m, "userPrincipalName", *e.Azure.PrincipalUpn) // frontend alias
	}
	if e.Azure.PrincipalMail != nil {
		setIfNotEmpty(m, "principalMail", *e.Azure.PrincipalMail)
	}
	if e.Azure.PrincipalJobTitle != nil {
		setIfNotEmpty(m, "principalJobTitle", *e.Azure.PrincipalJobTitle)
	}
	if e.Azure.PrincipalDepartment != nil {
		setIfNotEmpty(m, "principalDepartment", *e.Azure.PrincipalDepartment)
	}
	if e.Azure.PrincipalLastSignIn != nil {
		m["principalLastSignIn"] = e.Azure.PrincipalLastSignIn.UTC().Format("2006-01-02T15:04:05Z")
		m["lastSignInDateTime"] = e.Azure.PrincipalLastSignIn.UTC().Format("2006-01-02T15:04:05Z") // frontend alias
	}
	if e.Azure.PrincipalMfaRegistered != nil {
		m["principalMfaRegistered"] = *e.Azure.PrincipalMfaRegistered
		m["mfaRegistered"] = *e.Azure.PrincipalMfaRegistered // frontend alias
	}
	if e.Azure.PrincipalRiskLevel != nil {
		setIfNotEmpty(m, "principalRiskLevel", *e.Azure.PrincipalRiskLevel)
		setIfNotEmpty(m, "riskLevel", *e.Azure.PrincipalRiskLevel) // frontend alias
	}
	// Assignment fields
	if e.Azure.IsPermanent != nil {
		m["isPermanent"] = *e.Azure.IsPermanent
	}
	if e.Azure.AssignmentScope != nil {
		m["assignmentScope"] = *e.Azure.AssignmentScope
	}
	// PIM fields
	if e.Azure.AssignmentType != nil {
		m["assignmentType"] = *e.Azure.AssignmentType
	}
	if e.Azure.MemberType != nil {
		m["memberType"] = *e.Azure.MemberType
	}
	if e.Azure.ActivationDuration != nil {
		m["activationDuration"] = *e.Azure.ActivationDuration
	}
	if e.Azure.ActivatedAt != nil {
		m["activatedAt"] = e.Azure.ActivatedAt.UTC().Format("2006-01-02T15:04:05Z")
	}
	if e.Azure.ExpirationDateTime != nil {
		m["expirationDateTime"] = e.Azure.ExpirationDateTime.UTC().Format("2006-01-02T15:04:05Z")
	}
	if e.Azure.Justification != nil {
		m["justification"] = *e.Azure.Justification
	}
	if e.Azure.TicketInfo != nil {
		m["ticketInfo"] = *e.Azure.TicketInfo
	}
	if e.Azure.IsEligible != nil {
		m["isEligible"] = *e.Azure.IsEligible
	}
	if e.Azure.RequiresJustification != nil {
		m["requiresJustification"] = *e.Azure.RequiresJustification
	}
	if e.Azure.RequiresApproval != nil {
		m["requiresApproval"] = *e.Azure.RequiresApproval
	}

	// Build description from enriched fields if present
	if e.Azure.RoleName != nil && *e.Azure.RoleName != "" && e.DisplayName != "" {
		upn := ""
		if e.Azure.PrincipalUpn != nil {
			upn = *e.Azure.PrincipalUpn
		}
		assignType := "direct"
		if e.Azure.AssignmentType != nil && *e.Azure.AssignmentType != "" {
			assignType = *e.Azure.AssignmentType
		}
		if upn != "" {
			m["description"] = fmt.Sprintf("Principal: %s (%s) [%s]", e.DisplayName, upn, assignType)
		} else {
			m["description"] = fmt.Sprintf("Principal: %s [%s]", e.DisplayName, assignType)
		}
	}

	return m
}

func (e AffectedEntity) marshalAzureOAuth2Grant() map[string]interface{} {
	m := map[string]interface{}{
		"id":          e.DN, // DN contains Azure Object ID
		"displayName": e.DisplayName,
	}

	// Azure-specific fields
	if e.Azure.ClientAppId != nil {
		setIfNotEmpty(m, "clientAppId", *e.Azure.ClientAppId)
		setIfNotEmpty(m, "appId", *e.Azure.ClientAppId) // frontend alias
	}
	if e.Azure.ConsentType != nil {
		m["consentType"] = *e.Azure.ConsentType
	}
	if e.Azure.Scope != nil {
		m["scope"] = *e.Azure.Scope
	}
	if e.Azure.ResourceName != nil {
		setIfNotEmpty(m, "resourceDisplayName", *e.Azure.ResourceName)
	}
	if e.Azure.PermissionCategory != nil {
		setIfNotEmpty(m, "permissionCategory", *e.Azure.PermissionCategory)
	}

	// Build enriched description
	resourceName := ""
	if e.Azure.ResourceName != nil {
		resourceName = *e.Azure.ResourceName
	}
	scope := ""
	if e.Azure.Scope != nil {
		scope = *e.Azure.Scope
	}
	if e.DisplayName != "" && resourceName != "" && scope != "" {
		m["description"] = fmt.Sprintf("Consent granted to '%s' for %s on %s", e.DisplayName, scope, resourceName)
	} else if e.Azure.ConsentType != nil && scope != "" {
		m["description"] = fmt.Sprintf("Consent: %s, Scope: %s", *e.Azure.ConsentType, scope)
	}

	return m
}

func (e AffectedEntity) marshalAzureGeneric() map[string]interface{} {
	m := map[string]interface{}{
		"id":   e.DN,
		"type": e.Type,
	}
	setIfNotEmpty(m, "name", e.Name)
	setIfNotEmpty(m, "displayName", e.DisplayName)
	setIfNotEmpty(m, "description", e.Description)
	mergeSignInRiskContext(m, e.Azure)
	return m
}

// ===== End of Azure marshalling functions =====

func mergeSignInRiskContext(m map[string]interface{}, azure *AzureEntityFields) {
	if azure == nil || len(azure.SignInRiskContext) == 0 {
		return
	}
	for k, v := range azure.SignInRiskContext {
		if k == "" {
			continue
		}
		m[k] = v
	}
}

// JSON returns the JSON representation of the finding
func (f Finding) JSON() ([]byte, error) {
	return json.Marshal(f)
}

// JSON returns the JSON representation of the audit result
func (r AuditResult) JSON() ([]byte, error) {
	return json.Marshal(r)
}

// PrettyJSON returns pretty-printed JSON
func (r AuditResult) PrettyJSON() ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}
