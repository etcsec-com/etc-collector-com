// Package audit provides AD security vulnerability detection
package audit

import (
	"context"
	"time"

	"github.com/etcsec-com/etc-collector/internal/audit/exclusions"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// DetectorCategory represents a detector category
type DetectorCategory string

const (
	CategoryAccounts          DetectorCategory = "accounts"
	CategoryGroups            DetectorCategory = "groups"
	CategoryComputers         DetectorCategory = "computers"
	CategoryPermissions       DetectorCategory = "permissions"
	CategoryKerberos          DetectorCategory = "kerberos"
	CategoryPassword          DetectorCategory = "password"
	CategoryGPO               DetectorCategory = "gpo"
	CategoryTrusts            DetectorCategory = "trusts"
	CategoryADCS              DetectorCategory = "adcs"
	CategoryAttackPaths       DetectorCategory = "attack-paths"
	CategoryMonitoring        DetectorCategory = "monitoring"
	CategoryNetwork           DetectorCategory = "network"
	CategoryCompliance        DetectorCategory = "compliance"
	CategoryAdvanced          DetectorCategory = "advanced"
	CategoryConfig            DetectorCategory = "config"
	CategoryIdentity          DetectorCategory = "identity"          // Azure AD
	CategoryApplications      DetectorCategory = "applications"      // Azure AD
	CategoryPrivilegedAccess  DetectorCategory = "privilegedAccess"  // Azure AD
	CategoryConditionalAccess DetectorCategory = "conditionalAccess" // Azure AD
	CategoryDevices           DetectorCategory = "devices"           // Intune
	CategoryDeviceCompliance  DetectorCategory = "deviceCompliance"  // Intune
	CategoryAppProtection     DetectorCategory = "appProtection"     // Intune
	CategoryMailSecurity      DetectorCategory = "mailSecurity"      // Exchange Online
	CategoryMailFlow          DetectorCategory = "mailFlow"          // Exchange Online
	CategoryDLP               DetectorCategory = "dlp"               // Exchange Online
	CategoryOAuth             DetectorCategory = "oauth"             // Google Workspace
	CategoryDriveSharing      DetectorCategory = "driveSharing"      // Google Workspace
	CategoryWorkspaceAdmin    DetectorCategory = "workspaceAdmin"    // Google Workspace
	CategoryGuestExternal     DetectorCategory = "guestExternal"     // Azure AD
	CategoryRiskProtection    DetectorCategory = "riskProtection"    // Azure AD
	CategoryAzureCompliance   DetectorCategory = "azureCompliance"   // Azure AD
)

// Detector is the common interface for all detectors
type Detector interface {
	// ID returns the unique identifier (e.g., "STALE_ACCOUNT")
	ID() string

	// Category returns the detector category
	Category() DetectorCategory

	// Doc returns the catalog-facing metadata (title, description, worst
	// severity, source file). Populated by tools/cataloggen — every
	// detector that embeds BaseDetector gets a Doc() method written into
	// docs_gen.go in the same package. Catalog rendering (`make catalog`)
	// reads this metadata to regenerate docs/vulnerabilities/.
	Doc() DetectorDoc

	// Detect executes the detection and returns findings
	Detect(ctx context.Context, data *DetectorData) []types.Finding
}

// Tier0HelperConfig is a thin shadow of helpers.Tier0Config, defined here
// so the audit package can store it on DetectorData without importing the
// helpers package (which itself imports audit — would cycle). The audit
// engine fills this from the YAML loaded by helpers.LoadTier0Config.
//
// Mirrors helpers.Tier0Config field-for-field. Detectors use this struct
// directly via data.Tier0Config — no conversion needed.
type Tier0HelperConfig struct {
	Groups         []string
	OUs            []string
	MgmtSystems    []string
	AdminForestDNS []string
}

// GPOLink represents a link between a GPO and an OU/Site
type GPOLink struct {
	GPOCN       string `json:"gpoCN"`
	GPOGuid     string `json:"gpoGuid,omitempty"` // Alias
	LinkedTo    string `json:"linkedTo"`          // DN of OU/Site
	LinkEnabled bool   `json:"linkEnabled"`
	Disabled    bool   `json:"disabled,omitempty"` // Inverse of LinkEnabled
	Enforced    bool   `json:"enforced"`
	Order       int    `json:"order"`
}

// GPOAcl represents an ACL on a GPO
type GPOAcl struct {
	GPODN      string `json:"gpoDN"`
	Trustee    string `json:"trustee"`
	TrusteeSID string `json:"trusteeSID,omitempty"` // SID of trustee
	AccessMask int    `json:"accessMask"`
	AceType    string `json:"aceType"`
}

// Site represents an AD site
type Site struct {
	Name              string   `json:"name"`
	DistinguishedName string   `json:"distinguishedName"`
	Description       string   `json:"description,omitempty"`
	Servers           []string `json:"servers,omitempty"` // DCs in this site
}

// Subnet represents an AD subnet
type Subnet struct {
	Name              string `json:"name"`
	DistinguishedName string `json:"distinguishedName"`
	SiteDN            string `json:"siteDN"` // Reference to Site DN
	Description       string `json:"description,omitempty"`
}

// DCMetadata carries the per-DC enrichment fields (v3.1.29 §5) required by
// the INFO_DOMAIN_CONTROLLER detector. FSMORoles and ReplicationPartners
// are slice-of-string with the convention that an empty (non-nil) slice
// means "DC has none" — never nil in the emitted JSON.
type DCMetadata struct {
	FSMORoles           []string
	Site                string
	IsRODC              bool
	ReplicationPartners []string
}

// ObjectLookupEntry is the DTO returned by LDAPProvider.LookupBatch when
// the engine resolves ACL targets that aren't part of the typed collections.
// Kept narrow on purpose — only the fields needed to populate ObjectMeta.
type ObjectLookupEntry struct {
	DN             string
	CN             string
	SAMAccountName string
	ObjectClass    []string
	SID            string
}

// ObjectMeta is a DN-indexed lightweight handle on a collected AD object.
// Built once during engine.collectData and consumed by detectors that
// previously emitted bare {Type: "object", DN: …} entities (typically the
// permissions/ACL detectors, where the target of an ACE could be any class
// in the tree). Letting them look up the canonical EntityType + sAMAccountName
// from this cache fixes both the §1 (no more type='object') and §4.3
// (sAMAccountName 100% coverage) regressions in one place.
type ObjectMeta struct {
	DN             string
	SAMAccountName string
	Name           string
	EntityType     string

	// SID populated for user/group/computer (v3.1.29 §3) so the cache can
	// resolve ACL trustee SIDs back to a typed entity, and so SID-keyed
	// detectors can fall back to a domain-local match before declaring a
	// SID unresolved.
	SID string

	// Domain-specific overrides — populated only when EntityType == "domain".
	// Without these, an ACL that targets the domain root would emit a
	// {dn, name, type=domain} entity stripped of the multi-domain
	// disambiguation fields the SaaS dispatcher needs.
	NetBIOSName           string
	DomainSID             string
	ForestRoot            string
	FunctionalLevel       string
	DomainControllerCount int
}

// EntityForDN looks up a DN in the ObjectByDN cache and returns a typed
// AffectedEntity. Falls back to {Type: principal, DN: dn} when the DN
// isn't in the cache (rare — should only happen if a detector references
// an object not collected and not pulled in by the orphan resolution pass).
func (d *DetectorData) EntityForDN(dn string) types.AffectedEntity {
	if d.ObjectByDN != nil {
		if meta := d.ObjectByDN[dn]; meta != nil {
			return entityFromMeta(meta)
		}
	}
	// Cache miss: emit a principal with unresolved=true (v3.1.29 §3 contract).
	// We don't have a SID here — only the DN — so the SaaS dispatcher will see
	// a principal with `dn` set instead of `sid`, and `unresolved: true`.
	return types.AffectedEntity{Type: types.EntityTypePrincipal, DN: dn, Unresolved: true}
}

// entityFromMeta projects an ObjectMeta onto an AffectedEntity, propagating
// the domain-specific fields when EntityType is "domain" (so an ACL on the
// domain root carries netbiosName/domainSid/forestRoot/etc., not just dn+name).
func entityFromMeta(meta *ObjectMeta) types.AffectedEntity {
	ent := types.AffectedEntity{
		Type:           meta.EntityType,
		DN:             meta.DN,
		SAMAccountName: meta.SAMAccountName,
		Name:           meta.Name,
	}
	if meta.EntityType == types.EntityTypeDomain {
		ent.NetBIOSName = meta.NetBIOSName
		ent.DomainSID = meta.DomainSID
		ent.ForestRoot = meta.ForestRoot
		ent.FunctionalLevel = meta.FunctionalLevel
		ent.DomainControllerCount = meta.DomainControllerCount
	}
	return ent
}

// GetUniqueObjectEntities returns one typed AffectedEntity per unique ACL
// target DN, looking up its EntityType + sAMAccountName + name from the
// engine's DN-indexed cache (DetectorData.ObjectByDN). Falls back to
// EntityTypePrincipal (with empty SAM) for DNs that aren't in the cache —
// that should never happen in practice because engine.collectData resolves
// orphans via LDAPProvider.LookupBatch before detectors run, but keeps the
// failure mode visible (no silent regression to "object").
//
// Replaces helpers.GetUniqueObjects + the legacy
//
//	entities[i] = types.AffectedEntity{Type: "object", DN: dn}
//
// pattern that produced 56% of all entities as opaque "object" in v3.1.27.
func GetUniqueObjectEntities(entries []types.ACLEntry, byDN map[string]*ObjectMeta) []types.AffectedEntity {
	seen := make(map[string]bool, len(entries))
	out := make([]types.AffectedEntity, 0, len(entries))
	for _, ace := range entries {
		if ace.ObjectDN == "" || seen[ace.ObjectDN] {
			continue
		}
		seen[ace.ObjectDN] = true
		meta := byDN[ace.ObjectDN]
		if meta == nil {
			out = append(out, types.AffectedEntity{
				Type:       types.EntityTypePrincipal,
				DN:         ace.ObjectDN,
				Unresolved: true,
			})
			continue
		}
		out = append(out, entityFromMeta(meta))
	}
	return out
}

// DetectorData contains all data needed for detection
type DetectorData struct {
	// AD Objects
	Users             []types.User
	Groups            []types.Group
	Computers         []types.Computer
	OUs               []types.OU
	GPOs              []types.GPO
	Trusts            []types.Trust
	CertTemplates     []types.CertTemplate
	ACLEntries        []types.ACLEntry
	ObjectOwners      map[string]string // DN → Owner SID (for Owns edges)
	DomainControllers []types.Computer

	// ObjectByDN is the DN-indexed cache populated in engine.collectData
	// from all typed collections (Users/Groups/Computers/OUs/GPOs/CertTemplates/
	// DNSZones/Sites/Domain) plus a one-shot LDAP batch lookup that resolves
	// ACL targets which weren't in any typed collection (containers, schema
	// objects, AdminSDHolder, etc.).
	ObjectByDN map[string]*ObjectMeta

	// ObjectBySID is the SID-indexed reverse view of the same cache (v3.1.29).
	// Used by ACL detectors and aclEntry.trustee resolution to map a raw
	// trustee SID back to a typed entity (user/group/computer) before falling
	// back to wellKnownSid lookup or unresolved principal.
	ObjectBySID map[string]*ObjectMeta

	// DCInfo carries per-DC FSMO/site/RODC/replication metadata needed by
	// the INFO_DOMAIN_CONTROLLER detector (v3.1.29 §5). Keyed by DC DN.
	DCInfo map[string]*DCMetadata

	// GPO related
	GPOLinks []GPOLink
	GPOAcls  []GPOAcl

	// Sites and Subnets
	Sites   []Site
	Subnets []Subnet

	// Domain information
	DomainInfo *types.DomainInfo

	// SYSVOL/GPO policy data (Palier 2)
	GPOPolicies    map[string]*GPOPolicy // key = GPO GUID
	SYSVOLFindings []SYSVOLFinding

	// Fine-Grained Password Policies (PSOs)
	FGPPs []types.FGPP

	// v3.1.19 — Enterprise CAs from CN=Enrollment Services. Empty when LDAP
	// permission denied or no ADCS deployed. Used by ANSSI R36 (CA risks).
	CertAuthorities []types.CertAuthority

	// DNS zones from LDAP (Palier 3)
	DNSZones []types.DNSZone

	// Network probe results (Palier 3, nil if not enabled)
	NetworkProbes *types.NetworkProbeResults

	// Warnings collected during data gathering (probe failures, etc.)
	Warnings []types.Warning

	// Azure / Entra ID objects (nil when not applicable)
	AzureConditionalAccessPolicies []types.ConditionalAccessPolicy
	// AzureConditionalAccessPolicyDetails carries the full nested Microsoft
	// Graph shape for every CA policy. Used by the SaaS analyzer to compute
	// per-control adoption % (Token Protection, Sign-in Frequency, ...).
	AzureConditionalAccessPolicyDetails []types.ConditionalAccessPolicyDetail
	AzureDirectoryRoles                 []types.DirectoryRole
	AzureRoleAssignments                []types.RoleAssignment
	AzureAppRegistrations               []types.AppRegistration
	AzureServicePrincipals              []types.ServicePrincipal
	AzureOAuth2PermissionGrants         []types.OAuth2PermissionGrant
	AzureAuthMethodsPolicy              *types.AuthMethodsPolicy
	AzureNamedLocations                 []types.NamedLocation
	AzureRiskyUsers                     []types.RiskyUser
	AzureRiskySignIns                   []types.RiskySignIn
	AzureTenantConfig                   *types.AzureTenantConfig
	AzureLicenseTier                    string // "free", "p1", "p2"
	AzureTenantDomain                   string // default verified domain
	AzureMFACapableUsers                int
	AzureMFARegisteredUsers             int

	// v3.1.30 §1 — Azure sign-in logs deep collection. Mode is decided in
	// engine.collectAzureData based on RunOptions.AzureSignInLogsMode:
	//   - "raw" populates AzureSignInLogs with the full event stream
	//   - "aggregated" populates AzureSignInLogsAggregated only
	//   - "off" leaves both nil
	// Truncated/EventsCollected/OldestCollected are exposed regardless so
	// the SaaS knows the real lookback window and whether we hit the cap.
	AzureSignInLogs                []types.SignInLog
	AzureSignInLogsAggregated      *types.SignInLogsAggregated
	AzureSignInLogsTruncated       bool
	AzureSignInLogsEventsCollected int
	AzureSignInLogsOldestCollected time.Time
	// Transparency fields (v3.1.30 §1) — RequestedDays is what the operator
	// passed via --azure-signin-logs-days, ActualDays is what we actually
	// queried after clamping to Graph's 30-day retention. Surfaces silent
	// clamping that would otherwise leave the operator with incomplete data
	// they didn't realize was incomplete.
	AzureSignInLogsRequestedDays int
	AzureSignInLogsActualDays    int

	// v3.1.30 §3 — enriched OAuth grants summary. Built post-collection by
	// audit.SummarizeOAuthGrants from AzureOAuth2PermissionGrants (after
	// audit.EnrichOAuth2Grants resolves names + flags dangerous scopes).
	AzureOAuthGrantsSummary *types.OAuthGrantsSummary

	// v3.1.30 §4 — PIM (Privileged Identity Management) detail.
	// AzurePIMAssignments groups active + eligible + neverActivated for the
	// drift timeline. AzurePIMActivationHistory carries the 90-day request
	// log with justifications and ticket refs.
	AzurePIMAssignments       *types.PIMAssignmentsSummary
	AzurePIMActivationHistory *types.PIMActivationHistorySummary

	// v3.1.30 §5 — Cross-tenant access policy detail (B2B inbound trust map).
	// Default tenant-wide policy + per-partner overrides + Multi-Tenant Org
	// config. Powers the SaaS partner-trust map and detailed B2B audit.
	AzureCrossTenantAccess *types.CrossTenantAccessSummary

	// v3.1.30 §6 — Auth methods policy detail + strength policies + per-user
	// adoption stats (FIDO2 / Passwordless coverage, including admin sub-stat).
	AzureAuthMethodsDetail *types.AuthMethodsDetail

	// v3.1.30 §7 — Tenant-wide credential expiry rollup (per-app + per-SP
	// aggregates). Per-credential CredentialStatus and per-entity
	// CredentialSummary live directly on AzureAppRegistrations[]/
	// AzureServicePrincipals[] — already mutated in place by enrichAzureData.
	AzureCredentialExpiry *types.CredentialExpirySummary

	// v3.1.36 — Directory audit logs (last 90 days, 5 security categories).
	// Powers the SaaS Identity Drift Timeline + diff-vs-previous-audit views
	// + auditor evidence. Built post-collection from the raw events returned
	// by GetDirectoryAudits (sub-context budget, 5 categories in parallel).
	AzureDirectoryAudits *types.DirectoryAuditsSummary

	// v3.1.37 §1 — Authorization policy + admin consent request policy +
	// derived Microsoft Baseline Security Mode summary. The first two are
	// raw policy snapshots collected best-effort from /policies/* (single-
	// shot, no pagination). AzureBaselineSecurity is the per-tenant
	// adoption rollup over ~20 Microsoft baseline policies, derivable
	// purely from already-collected data — powers KPI #20.
	AzureAuthorizationPolicy       *types.AuthorizationPolicy
	AzureAdminConsentRequestPolicy *types.AdminConsentRequestPolicy
	AzureBaselineSecurity          *types.BaselineSecuritySummary

	// v3.1.37 §2 — Entra Backup & Recovery status (single-shot probe).
	// Fallback object with Available=false until Microsoft GAs the Graph
	// API; populated with real config once the probe returns 200 in a
	// future Microsoft release.
	AzureEntraBackup *types.EntraBackupStatus

	// v3.1.37 §3 — AI agent role assignments rollup (Silverfort Mar 2026
	// advisory). Filters AzureDirectoryRoles + AzureRoleAssignments by name
	// prefix (Agent / AI / Copilot / Knowledge) and expands Group
	// principals to count actual humans reachable. Powers KPI #26.
	AzureAIAgentRoles *types.AIAgentRolesSummary

	// v3.1.38 §1 — License info detail (License ROI matrix).
	// AzureSubscribedSkus is the full /subscribedSkus payload (formerly
	// discarded inside GetLicenseTier). The 3 governance counters are
	// best-effort single-shot probes; the *Probed flags distinguish
	// "endpoint not accessible" (Reason populated) from "endpoint probed
	// and feature genuinely not configured" (Dormant=true).
	AzureSubscribedSkus       []types.SubscribedSku
	AzureAccessReviewsCount   int
	AzureAccessReviewsProbed  bool
	AzureAccessPackagesCount  int
	AzureAccessPackagesProbed bool
	AzureVerifiedIDIssuers    int
	AzureVerifiedIDProbed     bool
	AzureLicenseInfo          *types.LicenseInfoSummary

	// T_058 (B_158) — same best-effort probe shape, feeding
	// AZ_NO_PRIVACY_STATEMENT and AZ_NO_TERMS_OF_USE (previously hard-coded
	// advisories with no data behind them).
	AzurePrivacyStatementURL    string
	AzurePrivacyStatementProbed bool
	AzureTermsOfUseCount        int
	AzureTermsOfUseProbed       bool

	// v3.1.38 §2 — Hybrid edges Entra ↔ AD. AzureDevices is collected
	// best-effort via GetDevices (paginated, sub-context budget). The
	// Truncated flag is set when the maxN cap stopped pagination early.
	// AzureCAESummary is the derived rollup at audit.cae (v3.1.39 §1).
	// Built post-collection from AzureConditionalAccessPolicyDetails — no
	// extra Graph roundtrip.
	AzureCAESummary *types.CAESummary

	// AzureFirstPartyAccounts is the derived rollup at audit.firstPartyAccounts
	// (v3.1.39 §2). Built post-collection from data.Users — no extra Graph
	// roundtrip.
	AzureFirstPartyAccounts *types.FirstPartyAccountsSummary

	// AzureMFARegistrationPolicy is the derived rollup at
	// audit.mfaRegistrationPolicy (v3.1.39 §3). Built post-collection from
	// AzureConditionalAccessPolicyDetails + AzureNamedLocations — no extra
	// Graph roundtrip.
	AzureMFARegistrationPolicy *types.MFARegistrationPolicySummary

	// AzureHybridLinks is the derived rollup at audit.hybridLinks.
	AzureDevices          []types.AzureDevice
	AzureDevicesTruncated bool
	AzureHybridLinks      *types.HybridLinksSummary

	// Replication metadata for temporal change detection (Sprint 3 Purple Knight parity)
	// SchemaSDLastChanged: when the nTSecurityDescriptor on the Schema NC was last modified
	SchemaSDLastChanged time.Time
	// DisplaySpecifierChanges: list of Display Specifier DNs modified in last 90 days
	DisplaySpecifierChanges []string
	// PrivilegedGroupMemberChanges: group DN → list of member DNs changed recently
	PrivilegedGroupMemberChanges map[string]map[string]time.Time

	// v3.1.19 — Tier 0 customer customization loaded from
	// <configDir>/tier0_groups.yaml. Optional; nil = use hardcoded defaults
	// only. Used by ANSSI helpers and detectors (R40, R69, R49+R50, R59, R86).
	Tier0Config *Tier0HelperConfig

	// Options
	IncludeDetails bool

	// Now is the reference time a detector must measure recency against —
	// "how long ago was X" — instead of calling time.Now()/time.Since()
	// itself (T_064/B_055). Set once by Engine.Run (RunOptions.AsOf, or the
	// real execution start when AsOf is zero) so every detector in a single
	// audit agrees on the same instant. A detector that reaches for the wall
	// clock directly makes its own result depend on WHEN it happens to run
	// rather than on the data — invisible on a live audit, but it means a
	// frozen recorded LDAP capture (docs/testing/snapshots/) stops replaying
	// reproducibly the moment enough real time passes, which defeats the
	// entire point of a frozen reference bench. Always non-zero once
	// populated by Engine.Run; a test building DetectorData directly should
	// set it explicitly for anything time-relative.
	Now time.Time

	// ExclusionReport captures which assets were filtered out (and why) during
	// collectData. Populated when the engine received RunOptions.Exclusions.
	// Appended to concurrently from runParallel detector goroutines; protected
	// by (*Engine).mu for per-detector entries — see dataForDetector in
	// engine.go. The lock deliberately lives on *Engine, not here: unlike
	// *Engine, a *DetectorData is value-copied (dataForDetector's per-detector
	// clone) on every filtered-exclusions run, and a sync.Mutex must never be
	// part of a struct that gets copied — go vet's copylocks check catches
	// exactly that (T_064/B_129).
	ExclusionReport *exclusions.Report
}

// buildSIDIndex builds a reverse SID-keyed view of an existing DN-indexed
// cache. Used by detectors that have a raw SID and want to map it back to
// a typed entity (user/group/computer). Domain-local match has priority over
// the static well-known SID lookup table.
func buildSIDIndex(byDN map[string]*ObjectMeta) map[string]*ObjectMeta {
	out := make(map[string]*ObjectMeta, len(byDN))
	for _, m := range byDN {
		if m.SID != "" {
			out[m.SID] = m
		}
	}
	return out
}

// buildObjectIndex assembles the DN-indexed cache from already-collected
// typed slices. Zero LDAP cost (everything is in memory). Called once by
// engine.collectData; orphans (ACL targets not in any typed collection)
// are then resolved via LDAPProvider.LookupBatch and added separately.
func buildObjectIndex(d *DetectorData) map[string]*ObjectMeta {
	size := len(d.Users) + len(d.Groups) + len(d.Computers) + len(d.OUs) + len(d.GPOs) + len(d.CertTemplates) + len(d.DNSZones) + len(d.Sites) + 1
	out := make(map[string]*ObjectMeta, size)
	for i := range d.Users {
		u := &d.Users[i]
		name := u.DisplayName
		if name == "" {
			name = u.SAMAccountName
		}
		out[u.DN] = &ObjectMeta{DN: u.DN, SAMAccountName: u.SAMAccountName, Name: name, EntityType: types.EntityTypeUser, SID: u.ObjectSID}
	}
	for i := range d.Groups {
		g := &d.Groups[i]
		name := g.DisplayName
		if name == "" {
			name = g.SAMAccountName
		}
		if name == "" {
			name = g.CN
		}
		out[g.DN] = &ObjectMeta{DN: g.DN, SAMAccountName: g.SAMAccountName, Name: name, EntityType: types.EntityTypeGroup, SID: g.ObjectSID}
	}
	for i := range d.Computers {
		c := &d.Computers[i]
		name := c.SAMAccountName
		if name == "" {
			name = c.DNSHostName
		}
		out[c.DN] = &ObjectMeta{DN: c.DN, SAMAccountName: c.SAMAccountName, Name: name, EntityType: types.EntityTypeComputer, SID: c.ObjectSID}
	}
	for i := range d.OUs {
		ou := &d.OUs[i]
		out[ou.DN] = &ObjectMeta{DN: ou.DN, Name: ou.Name, EntityType: types.EntityTypeOU}
	}
	for i := range d.GPOs {
		g := &d.GPOs[i]
		name := g.DisplayName
		if name == "" {
			name = g.Name
		}
		out[g.DN] = &ObjectMeta{DN: g.DN, Name: name, EntityType: types.EntityTypeGPO}
	}
	for i := range d.CertTemplates {
		t := &d.CertTemplates[i]
		name := t.Name
		if name == "" {
			name = t.DisplayName
		}
		out[t.DN] = &ObjectMeta{DN: t.DN, Name: name, EntityType: types.EntityTypeCertTemplate}
	}
	for i := range d.DNSZones {
		z := &d.DNSZones[i]
		if z.DN == "" {
			continue
		}
		out[z.DN] = &ObjectMeta{DN: z.DN, Name: z.Name, EntityType: types.EntityTypeDNSZone}
	}
	for i := range d.Sites {
		s := &d.Sites[i]
		out[s.DistinguishedName] = &ObjectMeta{DN: s.DistinguishedName, Name: s.Name, EntityType: types.EntityTypeSite}
	}
	if d.DomainInfo != nil && d.DomainInfo.DomainDN != "" {
		out[d.DomainInfo.DomainDN] = &ObjectMeta{
			DN:                    d.DomainInfo.DomainDN,
			Name:                  d.DomainInfo.DomainName,
			EntityType:            types.EntityTypeDomain,
			SID:                   d.DomainInfo.DomainSID,
			NetBIOSName:           d.DomainInfo.NetBIOSName,
			DomainSID:             d.DomainInfo.DomainSID,
			ForestRoot:            d.DomainInfo.ForestName,
			FunctionalLevel:       d.DomainInfo.FunctionalLevel,
			DomainControllerCount: len(d.DomainInfo.DomainControllers),
		}
	}
	return out
}

// DataLike-bridge methods so DetectorData satisfies
// internal/audit/exclusions.DataLike without an import cycle.
// See internal/audit/exclusions for the filter engine.

// GetUsers returns the users slice.
func (d *DetectorData) GetUsers() []types.User { return d.Users }

// SetUsers replaces the users slice.
func (d *DetectorData) SetUsers(u []types.User) { d.Users = u }

// GetGroups returns the groups slice.
func (d *DetectorData) GetGroups() []types.Group { return d.Groups }

// SetGroups replaces the groups slice.
func (d *DetectorData) SetGroups(g []types.Group) { d.Groups = g }

// GetComputers returns the computers slice.
func (d *DetectorData) GetComputers() []types.Computer { return d.Computers }

// SetComputers replaces the computers slice.
func (d *DetectorData) SetComputers(c []types.Computer) { d.Computers = c }

// GetOUs returns the OUs slice.
func (d *DetectorData) GetOUs() []types.OU { return d.OUs }

// SetOUs replaces the OUs slice.
func (d *DetectorData) SetOUs(o []types.OU) { d.OUs = o }

// BaseDetector provides common implementation
type BaseDetector struct {
	id       string
	category DetectorCategory
}

// NewBaseDetector creates a new base detector
func NewBaseDetector(id string, category DetectorCategory) BaseDetector {
	return BaseDetector{
		id:       id,
		category: category,
	}
}

// ID returns the detector ID
func (d *BaseDetector) ID() string {
	return d.id
}

// Category returns the detector category
func (d *BaseDetector) Category() DetectorCategory {
	return d.category
}
