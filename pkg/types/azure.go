package types

import "time"

// === Azure Entra ID Types ===
// Used by Azure security detectors to analyze tenant configuration.

// ConditionalAccessPolicy represents an Azure AD Conditional Access policy
type ConditionalAccessPolicy struct {
	ID               string    `json:"id"`
	DisplayName      string    `json:"displayName"`
	State            string    `json:"state"` // enabled, disabled, enabledForReportingButNotEnforced
	CreatedDateTime  time.Time `json:"createdDateTime,omitempty"`
	ModifiedDateTime time.Time `json:"modifiedDateTime,omitempty"`
	// Conditions — users
	IncludeUsers  []string `json:"includeUsers,omitempty"`
	ExcludeUsers  []string `json:"excludeUsers,omitempty"`
	IncludeGroups []string `json:"includeGroups,omitempty"`
	ExcludeGroups []string `json:"excludeGroups,omitempty"`
	IncludeRoles  []string `json:"includeRoles,omitempty"`
	ExcludeRoles  []string `json:"excludeRoles,omitempty"`
	// Conditions — apps
	IncludeApps []string `json:"includeApps,omitempty"`
	ExcludeApps []string `json:"excludeApps,omitempty"`
	// Conditions — locations
	IncludeLocations []string `json:"includeLocations,omitempty"`
	ExcludeLocations []string `json:"excludeLocations,omitempty"`
	// Conditions — client apps & platforms
	ClientAppTypes   []string `json:"clientAppTypes,omitempty"`
	IncludePlatforms []string `json:"includePlatforms,omitempty"`
	// Conditions — risk levels
	UserRiskLevels   []string `json:"userRiskLevels,omitempty"`
	SignInRiskLevels []string `json:"signInRiskLevels,omitempty"`
	// Grant controls
	GrantControls []string `json:"grantControls,omitempty"` // mfa, compliantDevice, domainJoinedDevice, etc.
	Operator      string   `json:"operator,omitempty"`      // AND or OR
	// Session controls
	SignInFrequencyValue    int    `json:"signInFrequencyValue,omitempty"`
	SignInFrequencyType     string `json:"signInFrequencyType,omitempty"`   // hours, days
	PersistentBrowserMode   string `json:"persistentBrowserMode,omitempty"` // always, never
	TokenProtectionRequired bool   `json:"tokenProtectionRequired,omitempty"`
}

// DirectoryRole represents an Azure AD directory role definition
type DirectoryRole struct {
	ID             string `json:"id"`
	DisplayName    string `json:"displayName"`
	Description    string `json:"description,omitempty"`
	RoleTemplateID string `json:"roleTemplateId"`
	IsBuiltIn      bool   `json:"isBuiltIn"`
	IsEnabled      bool   `json:"isEnabled"`
}

// RoleAssignment represents an Azure AD role assignment
type RoleAssignment struct {
	ID            string `json:"id"`
	PrincipalID   string `json:"principalId"`
	PrincipalName string `json:"principalName,omitempty"`
	PrincipalType string `json:"principalType,omitempty"` // User, Group, ServicePrincipal
	// Principal enrichment fields (populated via $expand=principal)
	UserPrincipalName   string    `json:"userPrincipalName,omitempty"`
	Mail                string    `json:"mail,omitempty"`
	PrincipalJobTitle   string    `json:"principalJobTitle,omitempty"`
	PrincipalDepartment string    `json:"principalDepartment,omitempty"`
	RoleID              string    `json:"roleDefinitionId"`
	RoleName            string    `json:"roleName,omitempty"`
	DirectoryScopeID    string    `json:"directoryScopeId,omitempty"`
	IsPermanent         bool      `json:"isPermanent"`
	StartDateTime       time.Time `json:"startDateTime,omitempty"`
	EndDateTime         time.Time `json:"endDateTime,omitempty"`
	// PIM (Privileged Identity Management) fields
	AssignmentType        string `json:"assignmentType,omitempty"`        // direct, eligible, activated
	MemberType            string `json:"memberType,omitempty"`            // direct, inherited
	ActivationDuration    string `json:"activationDuration,omitempty"`    // e.g., "PT8H" for 8 hours
	Justification         string `json:"justification,omitempty"`         // Activation justification
	TicketInfo            string `json:"ticketInfo,omitempty"`            // Ticket number/system
	ApproverName          string `json:"approverName,omitempty"`          // Who approved activation
	IsEligible            bool   `json:"isEligible,omitempty"`            // True if PIM-eligible
	RequiresJustification bool   `json:"requiresJustification,omitempty"` // PIM policy setting
	RequiresApproval      bool   `json:"requiresApproval,omitempty"`      // PIM policy setting
	// v3.1.30 §4 — first-assigned timestamp for the SaaS drift timeline.
	// Populated from /roleAssignmentSchedules.createdDateTime.
	CreatedDateTime time.Time `json:"createdDateTime,omitempty"`
}

// === v3.1.30 §4 — PIM (Privileged Identity Management) detail collection ===
//
// New top-level audit JSON keys: audit.pimAssignments + audit.pimActivationHistory.
// Surface "who got a permanent role and when" for the RSSI drift timeline,
// plus 90-day activation history (justifications, ticket refs, approvers).

// PIMAssignmentEntry is a single principal-role-scope binding, used in both
// active.byRole and eligible.byRole. EndDateTime nil = permanent.
type PIMAssignmentEntry struct {
	PrincipalID      string     `json:"principalId"`
	PrincipalUpn     string     `json:"principalUpn,omitempty"`
	PrincipalName    string     `json:"principalName,omitempty"`
	AssignmentType   string     `json:"assignmentType"`       // Assigned | Activated | Eligible
	MemberType       string     `json:"memberType,omitempty"` // Direct | Group | Inherited
	DirectoryScopeID string     `json:"directoryScopeId,omitempty"`
	StartDateTime    *time.Time `json:"startDateTime,omitempty"`
	EndDateTime      *time.Time `json:"endDateTime,omitempty"`     // null = permanent
	CreatedDateTime  *time.Time `json:"createdDateTime,omitempty"` // first time the binding was created
}

// PIMNeverActivatedEntry — eligible assignment with zero selfActivate events
// in the 90-day history window. Candidate for revocation.
type PIMNeverActivatedEntry struct {
	PrincipalID     string     `json:"principalId"`
	PrincipalUpn    string     `json:"principalUpn,omitempty"`
	PrincipalName   string     `json:"principalName,omitempty"`
	RoleDisplayName string     `json:"roleDisplayName"`
	EligibleSince   *time.Time `json:"eligibleSince,omitempty"`
	LastActivation  *time.Time `json:"lastActivation"` // always null in this slice
}

// PIMActiveSummary — active assignments breakdown.
type PIMActiveSummary struct {
	Total            int                             `json:"total"`
	ByAssignmentType map[string]int                  `json:"byAssignmentType"` // {"Assigned": N, "Activated": M}
	ByRole           map[string][]PIMAssignmentEntry `json:"byRole"`           // role display name → entries
}

// PIMEligibleSummary — eligible assignments breakdown.
type PIMEligibleSummary struct {
	Total  int                             `json:"total"`
	ByRole map[string][]PIMAssignmentEntry `json:"byRole"`
}

// PIMAssignmentsSummary lands at audit.pimAssignments.
type PIMAssignmentsSummary struct {
	Active         PIMActiveSummary         `json:"active"`
	Eligible       PIMEligibleSummary       `json:"eligible"`
	NeverActivated []PIMNeverActivatedEntry `json:"neverActivated"`
}

// PIMScheduleRequest mirrors a /roleAssignmentScheduleRequests entry.
// One row per PIM action (selfActivate / adminAssign / etc.).
type PIMScheduleRequest struct {
	ID                string     `json:"id"`
	Action            string     `json:"action"` // selfActivate | selfDeactivate | adminAssign | adminUpdate | adminRemove | adminRenew | adminExtend
	PrincipalID       string     `json:"principalId"`
	PrincipalUpn      string     `json:"principalUpn,omitempty"`
	PrincipalName     string     `json:"principalName,omitempty"`
	RoleID            string     `json:"roleId"`
	RoleDisplayName   string     `json:"roleDisplayName,omitempty"`
	DirectoryScopeID  string     `json:"directoryScopeId,omitempty"`
	Justification     string     `json:"justification,omitempty"`
	TicketNumber      string     `json:"ticketNumber,omitempty"`
	TicketSystem      string     `json:"ticketSystem,omitempty"`
	Status            string     `json:"status,omitempty"`
	CreatedDateTime   *time.Time `json:"createdDateTime,omitempty"`
	CompletedDateTime *time.Time `json:"completedDateTime,omitempty"`
}

// PIMActivationHistorySummary lands at audit.pimActivationHistory.
type PIMActivationHistorySummary struct {
	TotalRequests int                  `json:"totalRequests"`
	ByAction      map[string]int       `json:"byAction"`
	Events        []PIMScheduleRequest `json:"events"`
}

// === v3.1.30 §5 — Cross-tenant access policy detail ===
//
// Surfaces the full B2B / Direct Connect / Tenant Restrictions matrix from
// /policies/crossTenantAccessPolicy/{default,partners} so the SaaS analyzer
// can flag overly-open trusts and build the partner trust map. Today's B2B
// detectors only emit binary flags (B2B_INBOUND_TRUST_ALL etc.) without
// per-partner detail.

// CrossTenantAccessTarget — one access scope (usersAndGroups OR applications).
type CrossTenantAccessTarget struct {
	AccessType string   `json:"accessType,omitempty"` // allowed | blocked
	Targets    []string `json:"targets,omitempty"`    // group/role IDs or "AllUsers"/"AllApplications"
}

// CrossTenantAccessChannel groups the two access scopes.
type CrossTenantAccessChannel struct {
	UsersAndGroups CrossTenantAccessTarget `json:"usersAndGroups,omitempty"`
	Applications   CrossTenantAccessTarget `json:"applications,omitempty"`
}

// CrossTenantInboundTrust — flags MFA / device acceptance from external tenants.
type CrossTenantInboundTrust struct {
	IsMfaAccepted                       bool `json:"isMfaAccepted"`
	IsCompliantDeviceAccepted           bool `json:"isCompliantDeviceAccepted"`
	IsHybridAzureADJoinedDeviceAccepted bool `json:"isHybridAzureADJoinedDeviceAccepted"`
}

// CrossTenantTenantRestrictions — tenant restrictions v2 controls.
type CrossTenantTenantRestrictions struct {
	UsersAndGroups CrossTenantAccessTarget `json:"usersAndGroups,omitempty"`
	Applications   CrossTenantAccessTarget `json:"applications,omitempty"`
}

// CrossTenantAutomaticUserConsent — per-partner auto-consent settings.
type CrossTenantAutomaticUserConsent struct {
	InboundAllowed  bool `json:"inboundAllowed"`
	OutboundAllowed bool `json:"outboundAllowed"`
}

// CrossTenantPolicyChannels — bundles inbound + outbound for B2B Collaboration / Direct Connect.
type CrossTenantPolicyChannels struct {
	Inbound  CrossTenantAccessChannel `json:"inbound,omitempty"`
	Outbound CrossTenantAccessChannel `json:"outbound,omitempty"`
}

// CrossTenantDefaultPolicy — the tenant-wide default cross-tenant config.
type CrossTenantDefaultPolicy struct {
	B2BCollaboration   CrossTenantPolicyChannels     `json:"b2bCollaboration,omitempty"`
	B2BDirectConnect   CrossTenantPolicyChannels     `json:"b2bDirectConnect,omitempty"`
	InboundTrust       CrossTenantInboundTrust       `json:"inboundTrust,omitempty"`
	TenantRestrictions CrossTenantTenantRestrictions `json:"tenantRestrictions,omitempty"`
}

// CrossTenantPartnerPolicy — per-partner config overriding the default.
type CrossTenantPartnerPolicy struct {
	TenantID             string                          `json:"tenantId"`
	DisplayName          string                          `json:"displayName,omitempty"`
	IsServiceProvider    bool                            `json:"isServiceProvider"`
	IsInMultiTenantOrg   bool                            `json:"isInMultiTenantOrg,omitempty"`
	B2BCollaboration     CrossTenantPolicyChannels       `json:"b2bCollaboration,omitempty"`
	B2BDirectConnect     CrossTenantPolicyChannels       `json:"b2bDirectConnect,omitempty"`
	InboundTrust         CrossTenantInboundTrust         `json:"inboundTrust,omitempty"`
	AutomaticUserConsent CrossTenantAutomaticUserConsent `json:"automaticUserConsent,omitempty"`
}

// CrossTenantMultiTenantOrg — Microsoft 365 Multi-Tenant Organization (2024+).
type CrossTenantMultiTenantOrg struct {
	IsEnabled    bool `json:"isEnabled"`
	TenantsCount int  `json:"tenantsCount"`
}

// CrossTenantAccessSummary lands at audit.crossTenantAccess.
type CrossTenantAccessSummary struct {
	Default                 *CrossTenantDefaultPolicy  `json:"default,omitempty"`
	Partners                []CrossTenantPartnerPolicy `json:"partners,omitempty"`
	MultiTenantOrganization *CrossTenantMultiTenantOrg `json:"multiTenantOrganization,omitempty"`
}

// RolePIMPolicy represents PIM policy settings for a role
type RolePIMPolicy struct {
	RoleDefinitionID      string
	ScopeID               string
	MaximumDuration       string // ISO 8601, e.g., "PT8H"
	RequiresJustification *bool
	RequiresApproval      *bool
}

// AppRegistration represents an Azure AD app registration
type AppRegistration struct {
	ID                     string              `json:"id"`
	AppID                  string              `json:"appId"`
	DisplayName            string              `json:"displayName"`
	CreatedDateTime        time.Time           `json:"createdDateTime,omitempty"`
	SignInAudience         string              `json:"signInAudience"` // AzureADMyOrg, AzureADMultipleOrgs, AzureADandPersonalMicrosoftAccount
	RequiredResourceAccess []AppResourceAccess `json:"requiredResourceAccess,omitempty"`
	PasswordCredentials    []AppCredential     `json:"passwordCredentials,omitempty"`
	KeyCredentials         []AppCredential     `json:"keyCredentials,omitempty"`
	Owners                 []string            `json:"owners,omitempty"`    // displayName of each owner
	OwnerUpns              []string            `json:"ownerUpns,omitempty"` // UPN of each owner
	ReplyURLs              []string            `json:"replyUrls,omitempty"`
	ImplicitGrantEnabled   bool                `json:"implicitGrantEnabled,omitempty"`
	PublisherDomain        *string             `json:"publisherDomain,omitempty"`
	Homepage               *string             `json:"homepage,omitempty"`
	LogoutUrl              *string             `json:"logoutUrl,omitempty"`
	// Enriched fields
	LastSignInDateTime *time.Time `json:"lastSignInDateTime,omitempty"` // via associated SP
	ApiPermissions     []string   `json:"apiPermissions,omitempty"`     // all permissions (human-readable)

	// v3.1.30 §7 — per-app rollup of credential expiry buckets, computed during
	// enrichAzureData. Lets the SaaS dashboard sort/filter apps by urgency
	// without re-iterating each cred.
	CredentialSummary *CredentialSummary `json:"credentialSummary,omitempty"`
}

// AppResourceAccess represents API permissions requested by an app
type AppResourceAccess struct {
	ResourceAppID string          `json:"resourceAppId"`
	ResourceName  string          `json:"resourceName,omitempty"`
	Permissions   []AppPermission `json:"permissions,omitempty"`
}

// AppPermission represents a single API permission
type AppPermission struct {
	ID   string `json:"id"`
	Type string `json:"type"` // Role (application), Scope (delegated)
	Name string `json:"name,omitempty"`
}

// AppCredential represents a secret or certificate on an app/SP
type AppCredential struct {
	KeyID       string    `json:"keyId"`
	DisplayName string    `json:"displayName,omitempty"`
	Type        string    `json:"type"` // password, certificate
	StartDate   time.Time `json:"startDateTime"`
	EndDate     time.Time `json:"endDateTime"`
	// Certificate-only fields (populated when Type == "certificate")
	Thumbprint string `json:"thumbprint,omitempty"` // customKeyIdentifier hex
	Usage      string `json:"usage,omitempty"`      // e.g. Sign, Verify

	// v3.1.30 §7 — computed countdown to spare every consumer (SaaS analyzer,
	// reports, dashboards) a redundant date subtraction. Populated by
	// audit.EnrichApplications / EnrichServicePrincipals during enrichAzureData.
	CredentialStatus *AppCredentialStatus `json:"credentialStatus,omitempty"`
}

// AppCredentialStatus — derived expiry view of one AppCredential.
// Pure derivation from EndDate at audit time; no Graph fields involved.
type AppCredentialStatus struct {
	DaysUntilExpiry int       `json:"daysUntilExpiry"` // negative for expired
	Bucket          string    `json:"bucket"`          // expired | expiring_7d | expiring_30d | expiring_60d | expiring_90d | valid | unknown
	IsExpired       bool      `json:"isExpired"`
	ComputedAt      time.Time `json:"computedAt"` // lets the SaaS recompute days if analysis is delayed
}

// CredentialSummary — per-app/SP rollup of credential expiry buckets.
// Lives inside AppRegistration.CredentialSummary and ServicePrincipal.CredentialSummary.
// EarliestExpiry includes already-expired credentials; EarliestNonExpiredExpiry
// is the actionable date (when the next still-valid cred will expire).
type CredentialSummary struct {
	TotalCredentials         int        `json:"totalCredentials"`
	ExpiredCount             int        `json:"expiredCount"`
	Expiring7dCount          int        `json:"expiring7dCount"`
	Expiring30dCount         int        `json:"expiring30dCount"`
	Expiring60dCount         int        `json:"expiring60dCount"`
	Expiring90dCount         int        `json:"expiring90dCount"`
	ValidCount               int        `json:"validCount"`
	UnknownCount             int        `json:"unknownCount,omitempty"`
	EarliestExpiry           *time.Time `json:"earliestExpiry,omitempty"`
	EarliestNonExpiredExpiry *time.Time `json:"earliestNonExpiredExpiry,omitempty"`
	NearestExpiryBucket      string     `json:"nearestExpiryBucket,omitempty"` // most-urgent bucket present
}

// CredentialExpirySummary — tenant-wide rollup. Lands at audit.summary.credentialExpiry.
type CredentialExpirySummary struct {
	Applications      *CredentialEntityBucket `json:"applications,omitempty"`
	ServicePrincipals *CredentialEntityBucket `json:"servicePrincipals,omitempty"`
}

// CredentialEntityBucket — counters of how many entities (apps OR SPs) fall
// in each expiry bucket. "EntitiesWithExpired" counts entities that have at
// least one expired credential, etc. Buckets are inclusive (an entity with
// a 5-day-out cred AND a 60-day-out cred lands in BOTH Expiring7d and
// Expiring60d) — the SaaS dashboard groups by NearestExpiryBucket per entity
// for the cliff visualisation.
type CredentialEntityBucket struct {
	TotalEntities       int `json:"totalEntities"`
	EntitiesWithExpired int `json:"entitiesWithExpired"`
	EntitiesExpiring7d  int `json:"entitiesExpiring7d"`
	EntitiesExpiring30d int `json:"entitiesExpiring30d"`
	EntitiesExpiring60d int `json:"entitiesExpiring60d"`
	EntitiesExpiring90d int `json:"entitiesExpiring90d"`
}

// ServicePrincipal represents an Azure AD service principal
type ServicePrincipal struct {
	ID                        string          `json:"id"`
	AppID                     string          `json:"appId"`
	DisplayName               string          `json:"displayName"`
	ServicePrincipalType      string          `json:"servicePrincipalType"` // Application, ManagedIdentity, Legacy
	AccountEnabled            bool            `json:"accountEnabled"`
	AppOwnerOrganizationID    string          `json:"appOwnerOrganizationId,omitempty"`
	Owners                    []string        `json:"owners,omitempty"`    // displayName of each owner
	OwnerUpns                 []string        `json:"ownerUpns,omitempty"` // UPN of each owner
	PasswordCredentials       []AppCredential `json:"passwordCredentials,omitempty"`
	KeyCredentials            []AppCredential `json:"keyCredentials,omitempty"`
	AppRoleAssignmentRequired *bool           `json:"appRoleAssignmentRequired,omitempty"`
	CreatedDateTime           *time.Time      `json:"createdDateTime,omitempty"`
	LastSignInDateTime        *time.Time      `json:"lastSignInDateTime,omitempty"` // via signInActivity

	// v3.1.30 §3 — ConsentFix detection enrichments
	VerifiedPublisher  *VerifiedPublisher  `json:"verifiedPublisher,omitempty"`
	Tags               []string            `json:"tags,omitempty"`
	SignInAudience     string              `json:"signInAudience,omitempty"` // AzureADMyOrg | AzureADMultipleOrgs | AzureADandPersonalMicrosoftAccount | PersonalMicrosoftAccount
	AppRoleAssignments []AppRoleAssignment `json:"appRoleAssignments,omitempty"`

	// v3.1.30 §7 — per-SP rollup of credential expiry buckets, computed during
	// enrichAzureData. Mirror of AppRegistration.CredentialSummary.
	CredentialSummary *CredentialSummary `json:"credentialSummary,omitempty"`
}

// VerifiedPublisher (v3.1.30 §3) — Microsoft Verified Publisher metadata.
// Absence (or VerifiedPublisherID == "") on a multi-tenant SP is a yellow
// flag for ConsentFix campaigns since legitimate publishers can register
// trivially.
type VerifiedPublisher struct {
	DisplayName         string `json:"displayName,omitempty"`
	VerifiedPublisherID string `json:"verifiedPublisherId,omitempty"`
	AddedDateTime       string `json:"addedDateTime,omitempty"`
}

// AppRoleAssignment (v3.1.30 §3) represents an admin-consented application
// permission. Distinct from OAuth2PermissionGrant which represents user/admin
// delegated consent. AppRoleID resolves to a permission name via
// GraphPermissionNames; IsDangerous is true when the resolved name appears
// in DangerousGraphPermissions.
type AppRoleAssignment struct {
	ID                   string `json:"id"`
	PrincipalID          string `json:"principalId"` // SP that received the permission
	PrincipalDisplayName string `json:"principalDisplayName,omitempty"`
	PrincipalType        string `json:"principalType,omitempty"` // ServicePrincipal | User | Group
	ResourceID           string `json:"resourceId"`              // Target API SP (e.g. Microsoft Graph)
	ResourceDisplayName  string `json:"resourceDisplayName,omitempty"`
	AppRoleID            string `json:"appRoleId"`             // GUID of the granted permission
	AppRoleName          string `json:"appRoleName,omitempty"` // Resolved via GraphPermissionNames
	CreatedDateTime      string `json:"createdDateTime,omitempty"`
	IsDangerous          bool   `json:"isDangerous,omitempty"`
}

// OAuth2PermissionGrant represents a delegated permission consent
type OAuth2PermissionGrant struct {
	ID           string `json:"id"`
	ClientID     string `json:"clientId"`
	ClientName   string `json:"clientName,omitempty"`
	ClientAppID  string `json:"clientAppId,omitempty"` // appId of the client SP
	ConsentType  string `json:"consentType"`           // AllPrincipals, Principal
	PrincipalID  string `json:"principalId,omitempty"`
	ResourceID   string `json:"resourceId"`
	ResourceName string `json:"resourceName,omitempty"` // displayName of the resource SP (e.g. "Microsoft Graph")
	Scope        string `json:"scope"`                  // Space-separated permission scopes (kept as-is for backward compat with the 3 existing detectors)
	ExpiryTime   string `json:"expiryTime,omitempty"`   // ISO timestamp if limited

	// v3.1.30 §3 — ConsentFix detection enrichments. Additive only: legacy
	// callers reading .Scope / .ConsentType keep working unchanged.
	PrincipalUpn    string   `json:"principalUpn,omitempty"`    // UPN of the consenting user when ConsentType=Principal
	Scopes          []string `json:"scopes,omitempty"`          // Scope split on whitespace
	IsDangerous     bool     `json:"isDangerous,omitempty"`     // true when at least one scope is in DangerousGraphPermissions
	DangerousScopes []string `json:"dangerousScopes,omitempty"` // subset of Scopes that match DangerousGraphPermissions
}

// OAuthGrantsSummary (v3.1.30 §3) — output shape for the new
// audit.oauthGrants top-level key. Counters + per-consent-type breakdown +
// the full grants slice (already enriched via EnrichOAuth2Grants).
type OAuthGrantsSummary struct {
	TotalGrants    int                     `json:"totalGrants"`
	ByConsentType  map[string]int          `json:"byConsentType"`
	DangerousCount int                     `json:"dangerousCount"`
	Grants         []OAuth2PermissionGrant `json:"grants"`
}

// AuthMethodsPolicy represents the tenant authentication methods policy
type AuthMethodsPolicy struct {
	MicrosoftAuthenticator AuthMethodConfig `json:"microsoftAuthenticator"`
	FIDO2                  AuthMethodConfig `json:"fido2"`
	SMS                    AuthMethodConfig `json:"sms"`
	TemporaryAccessPass    AuthMethodConfig `json:"temporaryAccessPass"`
	Email                  AuthMethodConfig `json:"email"`
	PhoneVoice             AuthMethodConfig `json:"phoneVoice"`
	SoftwareOath           AuthMethodConfig `json:"softwareOath"`
	// v3.1.30 §6 — additional methods exposed by Graph that we now collect.
	HardwareOath            AuthMethodConfig `json:"hardwareOath,omitempty"`
	X509Certificate         AuthMethodConfig `json:"x509Certificate,omitempty"`
	QRCodePin               AuthMethodConfig `json:"qrCodePin,omitempty"`
	RegistrationEnforcement bool             `json:"registrationEnforcement"`
}

// AuthMethodConfig represents a single authentication method policy.
// v3.1.30 §6 — extended with per-method include/exclude targets and the
// per-method config sub-objects (FIDO2 attestation, MS Authenticator number
// matching, etc.). All extensions are additive — the 5 existing detectors
// keep reading .State unchanged.
type AuthMethodConfig struct {
	State        string   `json:"state"` // enabled, disabled
	TargetType   string   `json:"targetType,omitempty"`
	TargetGroups []string `json:"targetGroups,omitempty"`

	// v3.1.30 §6 — additive enrichments
	IncludeTargets []AuthMethodTarget             `json:"includeTargets,omitempty"`
	ExcludeTargets []AuthMethodTarget             `json:"excludeTargets,omitempty"`
	FIDO2          *AuthMethodFIDO2Config         `json:"fido2Config,omitempty"`
	Authenticator  *AuthMethodAuthenticatorConfig `json:"authenticatorConfig,omitempty"`
	SMSConfig      *AuthMethodSMSConfig           `json:"smsConfig,omitempty"`
	VoiceConfig    *AuthMethodVoiceConfig         `json:"voiceConfig,omitempty"`
}

// AuthMethodTarget — one principal/group included or excluded from a method.
type AuthMethodTarget struct {
	TargetType             string `json:"targetType"` // group | user
	ID                     string `json:"id"`
	IsRegistrationRequired bool   `json:"isRegistrationRequired,omitempty"`
}

// AuthMethodFIDO2Config — FIDO2-specific policy fields.
type AuthMethodFIDO2Config struct {
	IsAttestationEnforced            bool                       `json:"isAttestationEnforced"`
	IsSelfServiceRegistrationAllowed bool                       `json:"isSelfServiceRegistrationAllowed"`
	KeyRestrictions                  *AuthMethodKeyRestrictions `json:"keyRestrictions,omitempty"`
}

// AuthMethodKeyRestrictions — FIDO2 AAGUID allowlist/blocklist.
type AuthMethodKeyRestrictions struct {
	IsEnforced      bool     `json:"isEnforced"`
	EnforcementType string   `json:"enforcementType,omitempty"` // allow | block
	AAGuids         []string `json:"aaGuids,omitempty"`
}

// AuthMethodAuthenticatorConfig — Microsoft Authenticator features.
// numberMatchingRequiredState became Microsoft-mandatory Feb 2024 ; many
// tenants forgot to flip it to "enabled".
type AuthMethodAuthenticatorConfig struct {
	NumberMatchingRequiredState             string `json:"numberMatchingRequiredState,omitempty"` // enabled | disabled
	DisplayAppInformationRequiredState      string `json:"displayAppInformationRequiredState,omitempty"`
	DisplayLocationInformationRequiredState string `json:"displayLocationInformationRequiredState,omitempty"`
}

// AuthMethodSMSConfig — SMS-specific flags.
type AuthMethodSMSConfig struct {
	IsUsableForSignIn bool `json:"isUsableForSignIn"`
}

// AuthMethodVoiceConfig — Voice-specific flags.
type AuthMethodVoiceConfig struct {
	IsOfficePhoneAllowed bool `json:"isOfficePhoneAllowed"`
}

// === v3.1.30 §6 — Auth Strength Policies + per-user adoption ===

// AuthStrengthPolicy represents one /policies/authenticationStrengthPolicies entry.
type AuthStrengthPolicy struct {
	ID                    string   `json:"id"`
	DisplayName           string   `json:"displayName,omitempty"`
	Description           string   `json:"description,omitempty"`
	PolicyType            string   `json:"policyType"`                      // builtIn | custom
	RequirementsSatisfied string   `json:"requirementsSatisfied,omitempty"` // mfa | etc.
	AllowedCombinations   []string `json:"allowedCombinations,omitempty"`
}

// AuthStrengthSummary buckets strength policies by builtIn vs custom.
type AuthStrengthSummary struct {
	Total   int                  `json:"total"`
	BuiltIn []AuthStrengthPolicy `json:"builtIn,omitempty"`
	Custom  []AuthStrengthPolicy `json:"custom,omitempty"`
}

// UserRegistrationDetail is the per-user shape returned by
// /reports/authenticationMethods/userRegistrationDetails. Only used internally
// by audit.aggregateUserRegistrations — not surfaced in the JSON output to
// keep the payload bounded (a 10k-user tenant would otherwise add ~5 MB).
type UserRegistrationDetail struct {
	UserID                string   `json:"userId"`
	UserPrincipalName     string   `json:"userPrincipalName,omitempty"`
	UserDisplayName       string   `json:"userDisplayName,omitempty"`
	UserType              string   `json:"userType,omitempty"`
	IsAdmin               bool     `json:"isAdmin"`
	IsMFACapable          bool     `json:"isMfaCapable"`
	IsMFARegistered       bool     `json:"isMfaRegistered"`
	IsPasswordlessCapable bool     `json:"isPasswordlessCapable"`
	IsSSPRCapable         bool     `json:"isSsprCapable"`
	IsSSPREnabled         bool     `json:"isSsprEnabled"`
	IsSSPRRegistered      bool     `json:"isSsprRegistered"`
	MethodsRegistered     []string `json:"methodsRegistered,omitempty"`
	LastUpdatedDateTime   string   `json:"lastUpdatedDateTime,omitempty"`
}

// UserRegistrationStats aggregates UserRegistrationDetail into the audit
// payload — counters, per-method bucket, and an admin sub-stat.
type UserRegistrationStats struct {
	Total               int                    `json:"total"`
	MFACapable          int                    `json:"mfaCapable"`
	MFARegistered       int                    `json:"mfaRegistered"`
	PasswordlessCapable int                    `json:"passwordlessCapable"`
	FIDO2Registered     int                    `json:"fido2Registered"`
	ByMethod            map[string]int         `json:"byMethod"`
	AdminUsers          AdminRegistrationStats `json:"adminUsers"`
}

// AdminRegistrationStats — same counters scoped to isAdmin=true users.
type AdminRegistrationStats struct {
	Total           int `json:"total"`
	MFACapable      int `json:"mfaCapable"`
	MFARegistered   int `json:"mfaRegistered"`
	FIDO2Registered int `json:"fido2Registered"`
}

// AuthMethodsDetail lands at audit.authenticationMethodsDetail.
type AuthMethodsDetail struct {
	Policy                *AuthMethodsPolicy     `json:"policy,omitempty"`
	StrengthPolicies      *AuthStrengthSummary   `json:"strengthPolicies,omitempty"`
	UserRegistrationStats *UserRegistrationStats `json:"userRegistrationStats,omitempty"`
}

// NamedLocation represents an Azure AD named location
type NamedLocation struct {
	ID                                string   `json:"id"`
	DisplayName                       string   `json:"displayName"`
	IsTrusted                         bool     `json:"isTrusted"`
	IPRanges                          []string `json:"ipRanges,omitempty"`
	CountriesAndRegions               []string `json:"countriesAndRegions,omitempty"`
	IncludeUnknownCountriesAndRegions bool     `json:"includeUnknownCountriesAndRegions"`
}

// RiskyUser represents an Azure AD Identity Protection risky user
type RiskyUser struct {
	ID                string    `json:"id"`
	UserPrincipalName string    `json:"userPrincipalName"`
	UserDisplayName   string    `json:"userDisplayName,omitempty"`
	RiskLevel         string    `json:"riskLevel"` // low, medium, high, hidden, none
	RiskState         string    `json:"riskState"` // atRisk, confirmedCompromised, remediated, dismissed
	RiskDetail        string    `json:"riskDetail,omitempty"`
	RiskLastUpdated   time.Time `json:"riskLastUpdatedDateTime,omitempty"`
}

// RiskySignIn represents an Azure AD Identity Protection risky sign-in
type RiskySignIn struct {
	ID                string    `json:"id"`
	UserPrincipalName string    `json:"userPrincipalName"`
	UserDisplayName   string    `json:"userDisplayName,omitempty"`
	RiskLevel         string    `json:"riskLevel"`
	RiskState         string    `json:"riskState"`
	RiskDetail        string    `json:"riskDetail,omitempty"`
	DetectedDateTime  time.Time `json:"detectedDateTime,omitempty"`
	IPAddress         string    `json:"ipAddress,omitempty"`
	Location          string    `json:"location,omitempty"`
}

// AzureDevice mirrors a /devices entry. v3.1.38 §2 — collected to compute
// audit.hybridLinks.devices: counts per trustType + the slice of HAJ
// devices (TrustType=ServerAd) that are the actual hybrid bridges
// between AD and Entra. The DeviceID field is stable cross-Entra/AD so
// the SaaS analyzer can cross-ref it with Computer.objectGUID from an
// AD audit to reconstruct hybrid attack paths.
type AzureDevice struct {
	ID                    string     `json:"id"`
	DeviceID              string     `json:"deviceId"`
	DisplayName           string     `json:"displayName,omitempty"`
	TrustType             string     `json:"trustType"` // AzureAd | ServerAd | Workplace
	OperatingSystem       string     `json:"operatingSystem,omitempty"`
	OnPremisesSyncEnabled *bool      `json:"onPremisesSyncEnabled,omitempty"`
	AccountEnabled        *bool      `json:"accountEnabled,omitempty"`
	ApproximateLastSignIn *time.Time `json:"approximateLastSignIn,omitempty"`
}

// TenantSecurityDefaults represents security defaults status
type TenantSecurityDefaults struct {
	IsEnabled   bool   `json:"isEnabled"`
	DisplayName string `json:"displayName,omitempty"`
}

// AzureTenantConfig holds tenant-wide configuration for detectors
type AzureTenantConfig struct {
	SecurityDefaults        *TenantSecurityDefaults `json:"securityDefaults,omitempty"`
	UserRegistrationAllowed bool                    `json:"userRegistrationAllowed"`
	GuestInvitationPolicy   string                  `json:"guestInvitationPolicy,omitempty"`
	AdminPortalAccess       string                  `json:"adminPortalAccess,omitempty"`
	UserConsentPolicy       string                  `json:"userConsentPolicy,omitempty"`
	GroupCreationPolicy     string                  `json:"groupCreationPolicy,omitempty"`
	DeviceCodeFlowEnabled   bool                    `json:"deviceCodeFlowEnabled"`
	LinkedInSyncEnabled     bool                    `json:"linkedInSyncEnabled"`
}

// === Well-known role template IDs ===

const (
	AzureRoleGlobalAdmin            = "62e90394-69f5-4237-9190-012177145e10"
	AzureRoleSecurityAdmin          = "194ae4cb-b126-40b2-bd5b-6091b380977d"
	AzureRolePrivilegedRoleAdmin    = "e8611ab8-c189-46e8-94e1-60213ab1f814"
	AzureRoleUserAdmin              = "fe930be7-5e62-47db-91af-98c3a49a38b1"
	AzureRoleExchangeAdmin          = "29232cdf-9323-42fd-ade2-1d097af3e4de"
	AzureRoleSharePointAdmin        = "f28a1f50-f6e7-4571-818b-6a12f2af6b6c"
	AzureRoleCloudAppAdmin          = "158c047a-c907-4556-b7ef-446551a6b5f7"
	AzureRoleAppAdmin               = "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3"
	AzureRoleConditionalAccessAdmin = "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9"
	AzureRoleSecurityReader         = "5d6b6bb7-de71-4623-b4af-96380a352509"
)

// === Well-known Microsoft Graph resource app IDs ===

const (
	MicrosoftGraphAppID = "00000003-0000-0000-c000-000000000000"
)

// === Dangerous Graph permissions (application-level) ===

// GraphPermissionNames maps Graph permission GUIDs to human-readable names.
// Used to translate raw UUIDs from requiredResourceAccess into displayable names.
var GraphPermissionNames = map[string]string{
	// Application permissions (Role)
	"1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9": "Application.ReadWrite.All",
	"06b708a9-e830-4db3-a914-8e69da51d44f": "AppRoleAssignment.ReadWrite.All",
	"62a82d76-70ea-41e2-9197-370581804d09": "Group.ReadWrite.All",
	"5b567255-7703-4780-807c-7be8301ae99b": "Group.Read.All",
	"19dbc75e-c2e2-444c-a770-ec69d8559fc7": "Directory.ReadWrite.All",
	"7ab1d382-f21e-4acd-a863-ba3e13f7da61": "Directory.Read.All",
	"741f803b-c850-494e-b5df-cde7c675a1ca": "User.ReadWrite.All",
	"df021288-bdef-4463-88db-98f22de89214": "User.Read.All",
	"810c84a8-4a9e-49e6-bf7d-12d183f40d01": "Mail.Read",
	"e2a3a72e-5f79-4c64-b1b1-878b674786c9": "Mail.ReadWrite",
	"b633e1c5-b582-4048-a93e-9f11b44c7e96": "Mail.Send",
	"75359482-378d-4052-8f01-80520e7db3cd": "Files.ReadWrite.All",
	"01d4889c-1287-42c6-ac1f-5d1e02578ef6": "Files.Read.All",
	"9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8": "RoleManagement.ReadWrite.Directory",
	"483bed4a-2ad3-4361-a73b-c83ccdbdc53c": "RoleManagement.Read.Directory",
	"a82116e5-55eb-4c41-a434-62fe8a61c773": "Sites.FullControl.All",
	"332a536c-c7ef-4017-ab91-336970924f0d": "Sites.ReadWrite.All",
	"d13f72ca-a275-4b96-b789-48ebcc4da984": "Sites.Read.All",
	"ef54d2bf-783f-4e0f-bca1-3210c4d8f2f9": "Calendars.ReadWrite",
	"798ee544-9d2d-430c-a058-570e29e34338": "Calendars.Read",
	"9492366f-7969-46a4-8d15-ed1a20078fff": "AuditLog.Read.All",
	"b0afded3-3588-46d8-8b3d-9842eff778da": "AuditLog.Read.All", // alt guid
	// Delegated permissions (Scope)
	"e1fe6dd8-ba31-4d61-89e7-88639da4683d": "User.Read",
	"06da0dbc-49e2-44d2-8312-53f166ab848a": "Directory.Read.All (delegated)",
}

// DangerousGraphPermissions maps permission names to their GUIDs for Microsoft Graph.
// These are high-risk application permissions that grant broad access.
var DangerousGraphPermissions = map[string]string{
	"Mail.ReadWrite":                     "e2a3a72e-5f79-4c64-b1b1-878b674786c9",
	"Mail.Read":                          "810c84a8-4a9e-49e6-bf7d-12d183f40d01",
	"Files.ReadWrite.All":                "75359482-378d-4052-8f01-80520e7db3cd",
	"Directory.ReadWrite.All":            "19dbc75e-c2e2-444c-a770-ec69d8559fc7",
	"RoleManagement.ReadWrite.Directory": "9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8",
	"User.ReadWrite.All":                 "741f803b-c850-494e-b5df-cde7c675a1ca",
	"Group.ReadWrite.All":                "62a82d76-70ea-41e2-9197-370581804d09",
	"Application.ReadWrite.All":          "1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9",
	"AppRoleAssignment.ReadWrite.All":    "06b708a9-e830-4db3-a914-8e69da51d44f",
}
