package audit

import (
	"context"
	"fmt"
	"os"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/etcsec-com/etc-collector/internal/audit/compliance"
	"github.com/etcsec-com/etc-collector/internal/audit/exclusions"
	"github.com/etcsec-com/etc-collector/internal/providers"
	"github.com/etcsec-com/etc-collector/internal/providers/azure"
	"github.com/etcsec-com/etc-collector/internal/providers/network"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// SYSVOLProvider provides GPO policy data from SYSVOL (implemented by smb.Client)
type SYSVOLProvider interface {
	CollectGPOPolicies(gpos []types.GPO, domainName string) map[string]*GPOPolicy
	ScanSYSVOL(gpos []types.GPO, domainName string) []SYSVOLFinding
}

// Engine orchestrates the audit process
type Engine struct {
	registry       *Registry
	provider       providers.Provider
	sysvolProvider SYSVOLProvider

	// mu protects DetectorData.ExclusionReport.PerDetector against concurrent
	// appends from dataForDetector running inside runParallel goroutines
	// (T_064/B_129). Lives here rather than on DetectorData because
	// DetectorData is value-copied per detector when exclusions filter its
	// view (dataForDetector's `clone := *data`) — a sync.Mutex must never sit
	// on a struct that gets copied by value. *Engine never is.
	mu sync.Mutex
}

// NewEngine creates a new audit engine
func NewEngine(registry *Registry, provider providers.Provider) *Engine {
	if registry == nil {
		registry = DefaultRegistry
	}
	return &Engine{
		registry: registry,
		provider: provider,
	}
}

// SetProvider replaces the main data provider (e.g. LDAP client)
func (e *Engine) SetProvider(p providers.Provider) {
	e.provider = p
}

// SetSYSVOLProvider sets an optional SYSVOL provider for GPO policy collection
func (e *Engine) SetSYSVOLProvider(sp SYSVOLProvider) {
	e.sysvolProvider = sp
}

// HasSYSVOLProvider returns true if a SYSVOL provider is configured
func (e *Engine) HasSYSVOLProvider() bool {
	return e.sysvolProvider != nil
}

// DetectorCount returns the total number of registered detectors
func (e *Engine) DetectorCount() int {
	return len(e.registry.All())
}

// RunOptions configures the audit run
type RunOptions struct {
	// Categories to run (empty = all)
	Categories []DetectorCategory

	// Specific detector IDs to run (empty = all)
	DetectorIDs []string

	// Categories to subtract after the include set is built.
	// Applied after Categories / DetectorIDs.
	ExcludeCategories []DetectorCategory

	// Detector IDs to subtract after the include set is built.
	// Wins over every other selector.
	ExcludeDetectors []string

	// Include affected entities in findings
	IncludeDetails bool

	// Max users/groups/computers to fetch (0 = all)
	MaxUsers     int
	MaxGroups    int
	MaxComputers int

	// Parallel execution
	Parallel bool

	// Enable network probes (HTTP for ADCS ESC8, DNS zone transfer)
	NetworkProbes bool

	// Asset-level and detector-level exclusions. When non-nil and non-empty,
	// the engine filters users/computers/groups/OUs in collectData before
	// building objectDNs for ACL collection, and applies per-detector rules
	// in runSequential/runParallel before each detector is invoked.
	Exclusions *exclusions.Config

	// ExclusionsDryRun computes the exclusion report without actually filtering
	// the data slices. Lets auditors preview the impact of a config.
	ExclusionsDryRun bool

	// v3.1.19 — Path to the customer config directory. When set, the engine
	// looks for tier0_groups.yaml inside it and loads custom Tier 0 group
	// DNs / OUs / mgmt systems / admin forest DNS suffixes used by the
	// ANSSI compliance helpers and detectors. Empty = no customization,
	// fall back to the hardcoded defaults.
	ConfigDir string

	// v3.1.30 §1 — Azure sign-in logs deep collection.
	// AzureSignInLogsMode: "raw" (default) | "aggregated" | "off".
	// AzureSignInLogsDays: lookback window, capped at 30 by Graph retention.
	// AzureSignInLogsMax: hard cap on events fetched (default 500_000).
	// AzureAnonymizeIP: mask the last IPv4 octet of every emitted IP.
	AzureSignInLogsMode string
	AzureSignInLogsDays int
	AzureSignInLogsMax  int
	AzureAnonymizeIP    bool

	// v3.1.32 hotfix — sign-in logs collection runs in its own sub-context
	// with this budget (default 5 min). When the budget elapses, we keep
	// whatever events we collected, mark truncated=true, emit an
	// AZURE_SIGNIN_LOGS_TIMEOUT warning, and let the rest of collection +
	// the entire detection phase run on the parent context. Before this
	// fix a slow sign-in phase would consume the audit-wide deadline and
	// strand detection at 0 findings.
	AzureSignInLogsBudgetSeconds int

	// v3.1.36 — directory audits collection (90 days × 5 categories).
	// AzureDirectoryAuditsDays default 90 (clamped to 90 by Graph retention
	// for non-P1/P2 tenants). AzureDirectoryAuditsMax soft-caps the merged
	// event count (defaults to no cap). AzureDirectoryAuditsBudgetSeconds
	// runs the call in a sub-context (default 5 min) so a slow tenant
	// doesn't starve the detection phase, mirroring the sign-in logs
	// pattern from v3.1.32.
	AzureDirectoryAuditsDays          int
	AzureDirectoryAuditsMax           int
	AzureDirectoryAuditsBudgetSeconds int

	// v3.1.37 §1 — collector binary version, embedded in
	// audit.baselineSecurity.collectorVersion so an auditor can trace which
	// hardcoded baseline policy list applied to a given audit. Filled by
	// cmd/etc-collector at startup; safe to leave empty (the field becomes
	// omitempty in the JSON).
	CollectorVersion string

	// v3.1.38 §2 — Hybrid edges (Entra ↔ AD) collection. GetDevices is
	// run inside a sub-context with this budget (default 180 s). On
	// timeout we keep partial devices and emit
	// AZURE_HYBRID_LINKS_TIMEOUT, the rest of collection + detection
	// continues. Mirror of the v3.1.32 sign-in logs sub-context pattern.
	AzureHybridLinksBudgetSeconds int
	// AzureHybridLinksMax soft-caps the merged device count (defaults to
	// 0 = no cap). Truncation flag flows into audit.hybridLinks.devices.
	AzureHybridLinksMax int

	// AsOf overrides the reference time recency detectors measure against
	// (DetectorData.Now — see its doc comment) — T_064/B_055. Zero (the
	// default) means "the real moment this audit runs", exactly today's
	// behavior. Set explicitly to replay the frozen LDAP bench (or any
	// recorded input) against a FIXED point in time instead of the wall
	// clock: the whole reason a "30 days old" detector diverged between two
	// replays of the identical capture was that it measured against
	// time.Now() at replay time rather than against the moment the capture
	// was taken. Does not affect AuditResult.Timestamp/Duration, which still
	// reflect the real execution window.
	AsOf time.Time
}

// Run executes the audit
func (e *Engine) Run(ctx context.Context, opts RunOptions) (*types.AuditResult, error) {
	startTime := time.Now()

	// Collect data from provider
	data, err := e.collectData(ctx, opts)
	if err != nil {
		return nil, err
	}

	// T_064/B_055 — the reference time recency detectors measure against.
	// See RunOptions.AsOf and DetectorData.Now for why this exists.
	data.Now = opts.AsOf
	if data.Now.IsZero() {
		data.Now = startTime
	}

	// Get detectors to run
	detectors := e.selectDetectors(opts)

	// Run detectors. In dry-run mode we still compute per-detector rule hits
	// (for the report) but do NOT feed detectors a filtered view — so the
	// findings reflect what would be produced without any filter.
	var allFindings []types.Finding
	if opts.Parallel {
		allFindings = e.runParallel(ctx, detectors, data, opts.Exclusions, opts.ExclusionsDryRun)
	} else {
		allFindings = e.runSequential(ctx, detectors, data, opts.Exclusions, opts.ExclusionsDryRun)
	}

	// Filter out zero-count findings
	var findings []types.Finding
	for _, f := range allFindings {
		if f.Count > 0 {
			findings = append(findings, f)
		}
	}

	// Deterministic order (T_046/B_048): runParallel appends each detector's
	// results to a shared slice as goroutines complete, so the same input
	// produced a different finding order — and therefore a different
	// sha256 — on every run, defeating byte-for-byte regression comparison
	// (docs/testing/tools/audit-canonical-diff.py exists only to work around
	// this). A stable sort by Type is enough: it doesn't change which
	// findings exist or their content, only their position, and a detector
	// that itself emits several findings of its own Type (e.g.
	// KERBEROASTING_RISK) keeps its own internal order since ties are
	// resolved by original position.
	sort.SliceStable(findings, func(i, j int) bool { return findings[i].Type < findings[j].Type })

	// Decorate findings with cross-framework compliance mappings (no-op for
	// detectors that have no entry in compliance.mappings).
	compliance.EnrichWithCompliance(findings)
	// Compute per-framework score (carried via AuditResult, surfaced in the
	// TS conversion at SummarySection.ComplianceScores).
	complianceScores := compliance.CalculatePerFramework(findings)

	// Calculate statistics
	stats := e.calculateStats(findings, data)

	// Calculate score (entity-type weighted, normalized by users+computers+groups)
	score, scoreDetails := types.CalculateScore(findings, len(data.Users), len(data.Computers), len(data.Groups))
	rating := types.CalculateRating(score)

	// Build attack graph (BFS from non-privileged users to privileged targets)
	// All computation is local; only the resulting paths are exported to JSON.
	var attackGraph *types.AttackGraphExport
	if len(data.Users) > 0 && len(data.Groups) > 0 {
		agService := NewAttackGraphService(
			data.Users, data.Groups, data.Computers,
			data.ACLEntries, data.ObjectOwners, data.DomainInfo,
			data.OUs, data.GPOs, data.GPOLinks, data.GPOAcls,
			data.CertTemplates,
		)
		attackGraph = agService.Export(500)
	}

	// Build result
	result := &types.AuditResult{
		Timestamp:        startTime,
		Duration:         time.Since(startTime),
		Score:            score,
		Rating:           rating,
		ScoreDetails:     scoreDetails,
		Provider:         string(e.provider.Type()),
		Findings:         findings,
		Statistics:       stats,
		Summary:          e.buildSummary(findings),
		AttackGraph:      attackGraph,
		ComplianceScores: complianceScores,
		Exclusions:       exclusionsToExport(data.ExclusionReport),
	}

	// Add domain info if available
	if data.DomainInfo != nil {
		result.Domain = data.DomainInfo.DomainName
		result.DomainInfo = data.DomainInfo
	}

	// Propagate warnings from data collection (probe failures, etc.)
	if len(data.Warnings) > 0 {
		result.Warnings = append(result.Warnings, data.Warnings...)
	}

	// v3.1.30 §1 — propagate Azure sign-in logs to the result so they reach
	// the JSON output via ConvertToTSFormat / response.go.
	if data.AzureSignInLogs != nil {
		result.SignInLogs = data.AzureSignInLogs
	}
	if data.AzureSignInLogsAggregated != nil {
		result.SignInLogsAggregated = data.AzureSignInLogsAggregated
	}
	result.SignInLogsTruncated = data.AzureSignInLogsTruncated
	result.SignInLogsEventsCollected = data.AzureSignInLogsEventsCollected
	if !data.AzureSignInLogsOldestCollected.IsZero() {
		t := data.AzureSignInLogsOldestCollected
		result.SignInLogsOldestCollected = &t
	}
	result.SignInLogsRequestedDays = data.AzureSignInLogsRequestedDays
	result.SignInLogsActualDays = data.AzureSignInLogsActualDays

	// v3.1.30 §3 — propagate Azure OAuth grants summary + SP detail.
	if data.AzureOAuthGrantsSummary != nil {
		result.OAuthGrants = data.AzureOAuthGrantsSummary
	}
	if len(data.AzureServicePrincipals) > 0 {
		result.ServicePrincipals = data.AzureServicePrincipals
	}

	// v3.1.30 §4 — propagate PIM summaries.
	if data.AzurePIMAssignments != nil {
		result.PIMAssignments = data.AzurePIMAssignments
	}
	if data.AzurePIMActivationHistory != nil {
		result.PIMActivationHistory = data.AzurePIMActivationHistory
	}

	// v3.1.30 §5 — propagate cross-tenant access summary.
	if data.AzureCrossTenantAccess != nil {
		result.CrossTenantAccess = data.AzureCrossTenantAccess
	}

	// v3.1.30 §6 — propagate auth methods detail.
	if data.AzureAuthMethodsDetail != nil {
		result.AuthenticationMethodsDetail = data.AzureAuthMethodsDetail
	}

	// v3.1.30 §7 — propagate apps + tenant-wide credential expiry rollup.
	// Per-credential CredentialStatus and per-entity CredentialSummary are
	// already attached in place by enrichAzureData.
	if len(data.AzureAppRegistrations) > 0 {
		result.Applications = data.AzureAppRegistrations
	}
	if data.AzureCredentialExpiry != nil {
		result.CredentialExpiry = data.AzureCredentialExpiry
	}

	// v3.1.36 — directory audits summary (90 days, 5 categories).
	if data.AzureDirectoryAudits != nil {
		result.DirectoryAudits = data.AzureDirectoryAudits
	}

	// v3.1.37 §1 — Microsoft Baseline Security Mode adoption rollup.
	if data.AzureBaselineSecurity != nil {
		result.BaselineSecurity = data.AzureBaselineSecurity
	}

	// v3.1.37 §2 — Entra Backup & Recovery status probe.
	if data.AzureEntraBackup != nil {
		result.EntraBackup = data.AzureEntraBackup
	}

	// v3.1.37 §3 — AI agent role assignments rollup.
	if data.AzureAIAgentRoles != nil {
		result.AIAgentRoles = data.AzureAIAgentRoles
	}

	// v3.1.38 §1 — License ROI matrix detail.
	if data.AzureLicenseInfo != nil {
		result.LicenseInfo = data.AzureLicenseInfo
	}

	// v3.1.38 §2 — Hybrid edges Entra ↔ AD.
	if data.AzureHybridLinks != nil {
		result.HybridLinks = data.AzureHybridLinks
	}

	// v3.1.38 §3 — Conditional Access policies (full nested detail).
	if data.AzureConditionalAccessPolicyDetails != nil {
		result.ConditionalAccessPolicies = data.AzureConditionalAccessPolicyDetails
	}

	// v3.1.39 §1 — CAE tenant rollup.
	if data.AzureCAESummary != nil {
		result.CAE = data.AzureCAESummary
	}

	// v3.1.39 §2 — Bookings / first-party orphan accounts rollup.
	if data.AzureFirstPartyAccounts != nil {
		result.FirstPartyAccounts = data.AzureFirstPartyAccounts
	}

	// v3.1.39 §3 — MFA registration policy rollup.
	if data.AzureMFARegistrationPolicy != nil {
		result.MFARegistrationPolicy = data.AzureMFARegistrationPolicy
	}

	// Surface a warning when exclusions materially reduce the scanned set,
	// so SaaS dashboards and CLI users cannot silently game the score.
	if w := significantExclusionWarning(result.Exclusions); w != nil {
		result.Warnings = append(result.Warnings, *w)
	}

	return result, nil
}

// significantExclusionWarning returns a Warning describing a > 10% exclusion
// rate across any asset type, or nil if all types are below that threshold.
func significantExclusionWarning(r *types.ExclusionReport) *types.Warning {
	if r == nil || len(r.AssetCounts) == 0 {
		return nil
	}
	var flagged []string
	for typ, c := range r.AssetCounts {
		if c.Total == 0 {
			continue
		}
		pct := float64(c.Excluded) / float64(c.Total) * 100
		if pct >= 10.0 {
			flagged = append(flagged, typ)
		}
	}
	if len(flagged) == 0 {
		return nil
	}
	return &types.Warning{
		Code:    "ASSET_FILTER_SIGNIFICANT",
		Message: "Score based on filtered asset set — significant exclusions applied (rulesHash=" + r.RulesHash + ")",
	}
}

// collectData fetches data from the provider
func (e *Engine) collectData(ctx context.Context, opts RunOptions) (*DetectorData, error) {
	data := &DetectorData{
		IncludeDetails: opts.IncludeDetails,
	}

	// v3.1.19 — load Tier 0 customization from <configDir>/tier0_groups.yaml
	// if the file exists. Failures are logged but non-fatal: a malformed
	// YAML must not block the audit.
	if opts.ConfigDir != "" {
		// Engine has no logger today — print to stderr as a warning. The
		// audit run continues with default Tier 0 detection on YAML errors.
		if cfg, err := LoadTier0Config(opts.ConfigDir); err != nil {
			fmt.Fprintf(os.Stderr, "warning: failed to load tier0_groups.yaml (%v) — falling back to defaults\n", err)
		} else if cfg != nil {
			data.Tier0Config = &Tier0HelperConfig{
				Groups:         cfg.Groups,
				OUs:            cfg.OUs,
				MgmtSystems:    cfg.MgmtSystems,
				AdminForestDNS: cfg.AdminForestDNS,
			}
		}
	}

	// Fetch users
	userOpts := providers.QueryOptions{MaxResults: opts.MaxUsers}
	users, err := e.provider.GetUsers(ctx, userOpts)
	if err != nil {
		return nil, err
	}
	data.Users = users

	// Fetch groups
	groupOpts := providers.QueryOptions{MaxResults: opts.MaxGroups}
	groups, err := e.provider.GetGroups(ctx, groupOpts)
	if err != nil {
		return nil, err
	}
	data.Groups = groups

	// Fetch computers
	computerOpts := providers.QueryOptions{MaxResults: opts.MaxComputers}
	computers, err := e.provider.GetComputers(ctx, computerOpts)
	if err != nil {
		return nil, err
	}
	data.Computers = computers

	// Fetch domain info
	domainInfo, err := e.provider.GetDomainInfo(ctx)
	if err != nil {
		// Non-fatal, continue without domain info
		domainInfo = nil
	}
	data.DomainInfo = domainInfo

	// Fetch GPOs if provider supports it
	if ldapProvider, ok := e.provider.(LDAPProvider); ok {
		gpos, _ := ldapProvider.GetGPOs(ctx, providers.QueryOptions{})
		data.GPOs = gpos

		// Collect OUs (Organizational Units)
		ous, _ := ldapProvider.GetOUs(ctx, providers.QueryOptions{})
		data.OUs = ous

		// Collect GPO links from OUs and Sites
		gpoLinks, _ := ldapProvider.GetGPOLinks(ctx)
		data.GPOLinks = gpoLinks

		// Collect GPO ACLs
		var gpoDNs []string
		for _, gpo := range gpos {
			gpoDNs = append(gpoDNs, gpo.DN)
		}
		gpoAcls, _ := ldapProvider.GetGPOAcls(ctx, gpoDNs)
		data.GPOAcls = gpoAcls

		trusts, _ := ldapProvider.GetTrusts(ctx, providers.QueryOptions{})
		data.Trusts = trusts

		certs, _ := ldapProvider.GetCertTemplates(ctx, providers.QueryOptions{})
		data.CertTemplates = certs

		// v3.1.19 — Enterprise CAs (ANSSI R36)
		cas, _ := ldapProvider.GetCertAuthorities(ctx)
		data.CertAuthorities = cas

		// Collect DNS zones via LDAP (before ACLs so zone DNs can be included)
		dnsZones, dnsErr := ldapProvider.GetDNSZones(ctx)
		if dnsErr == nil {
			data.DNSZones = dnsZones
		}

		// Collect Fine-Grained Password Policies
		fgpps, fgppErr := ldapProvider.GetFGPPs(ctx)
		if fgppErr == nil {
			data.FGPPs = fgpps
		}

		// Collect Sites and Subnets (for SUBNET_MISSING detector)
		sites, subnets, _ := ldapProvider.GetSitesAndSubnets(ctx)
		data.Sites = sites
		data.Subnets = subnets
	}

	// === Apply asset-level exclusions ===
	// Done after Users/Groups/Computers/OUs are fetched but BEFORE DomainControllers
	// derivation, objectDNs build, and GetACLs. This ensures excluded assets never
	// appear in ACLs / DC list / detector inputs, and saves the LDAP round-trips
	// for GetACLs on excluded DNs.
	if cfg := opts.Exclusions; cfg != nil && !cfg.IsEmpty() {
		if opts.ExclusionsDryRun {
			// Compute report against a shadow view that doesn't mutate data.
			shadow := shadowData{DetectorData: data}
			data.ExclusionReport = exclusions.ApplyToData(shadow, cfg)
		} else {
			data.ExclusionReport = exclusions.ApplyToData(data, cfg)
		}
	}

	// Populate DomainControllers from (possibly filtered) Computers.
	// (SERVER_TRUST_ACCOUNT bit = 0x2000.)
	data.DomainControllers = nil
	for _, c := range data.Computers {
		if (c.UserAccountControl & 0x2000) != 0 {
			data.DomainControllers = append(data.DomainControllers, c)
		}
	}

	// v3.1.29 §5 — collect per-DC FSMO/site/RODC/replication metadata so the
	// INFO_DOMAIN_CONTROLLER detector can emit fully-typed dc entities.
	if ldapProvider, ok := e.provider.(LDAPProvider); ok && len(data.DomainControllers) > 0 {
		if meta, err := ldapProvider.GetDCMetadata(ctx, data.DomainControllers); err == nil {
			data.DCInfo = meta
		}
	}

	// Collect ACLs only for objects that survived the exclusion filter.
	if ldapProvider, ok := e.provider.(LDAPProvider); ok {
		// Collect ACLs for ALL objects (users, groups, computers, OUs)
		// All graph computation is done locally; only resulting attack paths are exported.
		var objectDNs []string
		for _, u := range data.Users {
			objectDNs = append(objectDNs, u.DN)
		}
		for _, g := range data.Groups {
			objectDNs = append(objectDNs, g.DN)
		}
		for _, c := range data.Computers {
			objectDNs = append(objectDNs, c.DN)
		}
		for _, ou := range data.OUs {
			objectDNs = append(objectDNs, ou.DN)
		}

		// Also add critical system objects
		if data.DomainInfo != nil && data.DomainInfo.DomainDN != "" {
			baseDN := data.DomainInfo.DomainDN
			objectDNs = append(objectDNs, baseDN) // Domain root
			objectDNs = append(objectDNs, "CN=AdminSDHolder,CN=System,"+baseDN)
			objectDNs = append(objectDNs, "CN=Policies,CN=System,"+baseDN)

			// ADCS PKI objects for ESC4/ESC5/ESC7 detection
			configDN := "CN=Configuration," + baseDN
			objectDNs = append(objectDNs, "CN=Public Key Services,CN=Services,"+configDN)
			objectDNs = append(objectDNs, "CN=Enrollment Services,CN=Public Key Services,CN=Services,"+configDN)

			// DPAPI master key container (for DPAPI_KEY_NON_DEFAULT_ACCESS detector)
			objectDNs = append(objectDNs, "CN=Master Root Keys,CN=System,"+baseDN)

			// Schema container (for SCHEMA_NON_STANDARD_PERMISSIONS detector)
			objectDNs = append(objectDNs, "CN=Schema,"+configDN)
		}

		// Add individual certificate template DNs for ESC4 ACL analysis
		for _, ct := range data.CertTemplates {
			objectDNs = append(objectDNs, ct.DN)
		}

		// Add DNS zone DNs for DNS_ZONE_AU_CREATE_CHILD detection
		for _, zone := range data.DNSZones {
			if zone.DN != "" {
				objectDNs = append(objectDNs, zone.DN)
			}
		}

		acls, owners, _ := ldapProvider.GetACLs(ctx, objectDNs)
		data.ACLEntries = acls
		data.ObjectOwners = owners

		// Build the DN-indexed ObjectByDN cache (v3.1.28). First pass fills
		// from already-typed collections (zero LDAP cost); second pass batch-
		// resolves any ACL target that wasn't in those collections (containers,
		// schema objects, AdminSDHolder, etc.) so detectors can emit a typed
		// AffectedEntity instead of the legacy bare {type:"object", dn:…}.
		data.ObjectByDN = buildObjectIndex(data)
		data.ObjectBySID = buildSIDIndex(data.ObjectByDN)
		var orphans []string
		seen := make(map[string]struct{})
		for _, ace := range data.ACLEntries {
			if ace.ObjectDN == "" {
				continue
			}
			if _, ok := data.ObjectByDN[ace.ObjectDN]; ok {
				continue
			}
			if _, ok := seen[ace.ObjectDN]; ok {
				continue
			}
			seen[ace.ObjectDN] = struct{}{}
			orphans = append(orphans, ace.ObjectDN)
		}
		if len(orphans) > 0 {
			if entries, err := ldapProvider.LookupBatch(ctx, orphans); err == nil {
				for _, e := range entries {
					name := e.CN
					if name == "" {
						name = e.SAMAccountName
					}
					meta := &ObjectMeta{
						DN:             e.DN,
						SAMAccountName: e.SAMAccountName,
						Name:           name,
						EntityType:     ObjectClassToEntityType(e.ObjectClass),
						SID:            e.SID,
					}
					data.ObjectByDN[e.DN] = meta
					if meta.SID != "" {
						data.ObjectBySID[meta.SID] = meta
					}
				}
			}
		}

		// Enrich Computer objects with ACL flags derived from ACLEntries.
		// This enables detectors like COMPUTER_ACL_ABUSE and COMPUTER_DCSYNC_RIGHTS
		// that read boolean flags instead of scanning raw ACLEntries.
		enrichACLFlags(data)

		// Collect replication metadata for temporal change detection (Sprint 3)
		if replProvider, ok := e.provider.(ReplMetadataProvider); ok && data.DomainInfo != nil {
			e.collectReplMetadata(ctx, replProvider, data)
		}
	}

	// Collect SYSVOL/GPO policy data if SMB provider is available
	if e.sysvolProvider != nil && data.DomainInfo != nil && data.DomainInfo.DomainDN != "" {
		// Derive DNS domain name from DomainDN (DC=example,DC=com → example.com)
		// DomainInfo.DomainName is the LDAP "name" attr (short name), SYSVOL needs FQDN
		domainName := dnToDNSName(data.DomainInfo.DomainDN)
		if domainName != "" {
			data.GPOPolicies = e.sysvolProvider.CollectGPOPolicies(data.GPOs, domainName)
			data.SYSVOLFindings = e.sysvolProvider.ScanSYSVOL(data.GPOs, domainName)
		}
	}

	// Run network probes if enabled (double opt-in: server + API)
	if opts.NetworkProbes && data.DomainInfo != nil {
		var dcs []string
		dcs = append(dcs, data.DomainInfo.DomainControllers...)
		probeResults, probeWarnings := network.RunNetworkProbes(ctx, data.CertTemplates, data.DNSZones, dcs)
		data.NetworkProbes = probeResults
		data.Warnings = probeWarnings
	}

	// Collect Azure AD / Entra ID data if provider supports it
	e.collectAzureData(ctx, data, opts)

	return data, nil
}

// dnToDNSName converts an LDAP DN to a DNS domain name
// e.g., "DC=example,DC=com" → "example.com"
func dnToDNSName(dn string) string {
	var parts []string
	for _, rdn := range strings.Split(dn, ",") {
		rdn = strings.TrimSpace(rdn)
		upper := strings.ToUpper(rdn)
		if strings.HasPrefix(upper, "DC=") {
			parts = append(parts, rdn[3:])
		}
	}
	return strings.Join(parts, ".")
}

// collectAzureData fetches Azure AD data if the provider implements AzureProvider
func (e *Engine) collectAzureData(ctx context.Context, data *DetectorData, opts RunOptions) {
	azProvider, ok := e.provider.(AzureProvider)
	if !ok {
		return
	}

	// B_157/T_058 — each of these ten best-effort fetches used to drop its
	// error silently on `err == nil` failure: the field stayed nil and every
	// downstream detector read that as "nothing to report" instead of "could
	// not read". This is the exact pattern that hid the GetRoleAssignments
	// bug (B_156) for 5 months. A Warning is the collector's own established
	// signal for "collection issue, not a security finding" (same mechanism
	// as AZURE_SIGNIN_LOGS_TIMEOUT below) — reused here rather than inventing
	// a parallel *Failed flag on DetectorData.
	if policies, err := azProvider.GetConditionalAccessPolicies(ctx); err == nil {
		data.AzureConditionalAccessPolicies = policies
	} else {
		data.Warnings = append(data.Warnings, types.Warning{Code: "AZURE_CONDITIONAL_ACCESS_POLICIES_FAILED", Message: err.Error()})
	}
	if roles, err := azProvider.GetDirectoryRoles(ctx); err == nil {
		data.AzureDirectoryRoles = roles
	} else {
		data.Warnings = append(data.Warnings, types.Warning{Code: "AZURE_DIRECTORY_ROLES_FAILED", Message: err.Error()})
	}
	if assignments, err := azProvider.GetRoleAssignments(ctx); err == nil {
		data.AzureRoleAssignments = assignments
	} else {
		data.Warnings = append(data.Warnings, types.Warning{Code: "AZURE_ROLE_ASSIGNMENTS_FAILED", Message: err.Error()})
	}
	if apps, err := azProvider.GetAppRegistrations(ctx, providers.QueryOptions{}); err == nil {
		data.AzureAppRegistrations = apps
	} else {
		data.Warnings = append(data.Warnings, types.Warning{Code: "AZURE_APP_REGISTRATIONS_FAILED", Message: err.Error()})
	}
	if sps, err := azProvider.GetServicePrincipals(ctx, providers.QueryOptions{}); err == nil {
		data.AzureServicePrincipals = sps
	} else {
		data.Warnings = append(data.Warnings, types.Warning{Code: "AZURE_SERVICE_PRINCIPALS_FAILED", Message: err.Error()})
	}
	if grants, err := azProvider.GetOAuth2PermissionGrants(ctx); err == nil {
		data.AzureOAuth2PermissionGrants = grants
	} else {
		data.Warnings = append(data.Warnings, types.Warning{Code: "AZURE_OAUTH2_GRANTS_FAILED", Message: err.Error()})
	}
	if authPolicy, err := azProvider.GetAuthMethodsPolicy(ctx); err == nil {
		data.AzureAuthMethodsPolicy = authPolicy
	} else {
		data.Warnings = append(data.Warnings, types.Warning{Code: "AZURE_AUTH_METHODS_POLICY_FAILED", Message: err.Error()})
	}
	if locations, err := azProvider.GetNamedLocations(ctx); err == nil {
		data.AzureNamedLocations = locations
	} else {
		data.Warnings = append(data.Warnings, types.Warning{Code: "AZURE_NAMED_LOCATIONS_FAILED", Message: err.Error()})
	}
	if riskyUsers, err := azProvider.GetRiskyUsers(ctx); err == nil {
		data.AzureRiskyUsers = riskyUsers
	} else {
		data.Warnings = append(data.Warnings, types.Warning{Code: "AZURE_RISKY_USERS_FAILED", Message: err.Error()})
	}
	if riskySignIns, err := azProvider.GetRiskySignIns(ctx); err == nil {
		data.AzureRiskySignIns = riskySignIns
	} else {
		data.Warnings = append(data.Warnings, types.Warning{Code: "AZURE_RISKY_SIGNINS_FAILED", Message: err.Error()})
	}

	// v3.1.30 §1 — sign-in logs deep collection.
	// Default mode = "raw" (per user decision: aggregating kills the SOC
	// patterns this collection enables — impossible travel, AITM, push
	// fatigue, etc. — which are all event-level).
	mode := opts.AzureSignInLogsMode
	if mode == "" {
		mode = "raw"
	}
	if mode != "off" {
		// Days clamping — surface what the operator asked for vs what we
		// actually collected. Silent clamping was rejected during plan
		// review: an operator asking for 60 days needs to know Graph caps
		// retention at 30 BEFORE they discover incomplete data weeks later.
		requestedDays := opts.AzureSignInLogsDays
		days := requestedDays
		if days <= 0 {
			days = 30
		}
		if days > 30 {
			fmt.Fprintf(os.Stderr,
				"warning: Microsoft Graph signIns retention max = 30 days, clamped from %d to 30\n",
				requestedDays)
			days = 30
		}
		data.AzureSignInLogsRequestedDays = requestedDays
		data.AzureSignInLogsActualDays = days

		// maxN > 0 is guaranteed by cmd/etc-collector/audit.go before the
		// engine runs — silent default was rejected in plan review.
		maxN := opts.AzureSignInLogsMax

		// v3.1.32 hotfix — sign-in collection runs in its own sub-context
		// with a budget (default 5 min). When the budget elapses, GetSignInLogs
		// returns context.DeadlineExceeded; we keep partial events, mark
		// truncated=true, emit AZURE_SIGNIN_LOGS_TIMEOUT, and the parent ctx
		// is unchanged so the rest of collection + detection still run.
		// Before this fix a slow sign-in phase consumed the audit-wide
		// deadline and stranded detection at 0 findings (the Reddit-grade
		// "score 100/0 findings" regression on tenants with >1k sign-ins).
		budget := time.Duration(opts.AzureSignInLogsBudgetSeconds) * time.Second
		if budget <= 0 {
			budget = 5 * time.Minute
		}
		signInCtx, signInCancel := context.WithTimeout(ctx, budget)
		logs, truncated, oldest, err := azProvider.GetSignInLogs(signInCtx, days, maxN)
		signInCancel()
		if err != nil {
			code := "AZURE_SIGNIN_LOGS_FAILED"
			msg := err.Error()
			// Distinguish budget timeout from upstream Graph failures —
			// the SaaS analyzer routes these differently (timeout = retry
			// next cycle, failure = surface to operator).
			if signInCtx.Err() == context.DeadlineExceeded && ctx.Err() == nil {
				code = "AZURE_SIGNIN_LOGS_TIMEOUT"
				msg = fmt.Sprintf("sign-in logs collection exceeded %s budget (collected %d events before timeout)", budget, len(logs))
				truncated = true
			}
			data.Warnings = append(data.Warnings, types.Warning{
				Code:    code,
				Message: msg,
			})
		}
		// Always materialize whatever we got (partial counts on timeout).
		if logs != nil {
			if opts.AzureAnonymizeIP {
				AnonymizeSignInIPs(logs)
			}
			data.AzureSignInLogsTruncated = truncated
			data.AzureSignInLogsEventsCollected = len(logs)
			data.AzureSignInLogsOldestCollected = oldest
			switch mode {
			case "aggregated":
				data.AzureSignInLogsAggregated = AggregateSignInLogs(logs)
			default: // raw
				data.AzureSignInLogs = logs
			}
		}
	}
	if tenantCfg, err := azProvider.GetTenantConfig(ctx); err == nil {
		data.AzureTenantConfig = tenantCfg
		// Also fetch security defaults into tenant config if not already set
		if tenantCfg.SecurityDefaults == nil {
			if sd, err := azProvider.GetSecurityDefaults(ctx); err == nil {
				tenantCfg.SecurityDefaults = sd
			}
		}
	}

	// License tier detection. v3.1.38 §1 — collect /subscribedSkus once and
	// derive the tier from the same payload (the legacy GetLicenseTier call
	// would have refetched the same endpoint and discarded the detail). The
	// detailed slice lives on data.AzureSubscribedSkus and feeds the
	// audit.licenseInfo rollup later in this function.
	if lip, hasLicenseInfo := e.provider.(licenseInfoProvider); hasLicenseInfo {
		if skus, err := lip.GetSubscribedSkus(ctx); err == nil && skus != nil {
			data.AzureSubscribedSkus = skus
			data.AzureLicenseTier = azure.DeriveLicenseTier(skus)
		} else {
			// Best-effort fallback to the legacy tier-only call if the
			// provider doesn't implement the v3.1.38 interface or the
			// request itself failed.
			data.AzureLicenseTier = azProvider.GetLicenseTier(ctx)
		}
	} else {
		data.AzureLicenseTier = azProvider.GetLicenseTier(ctx)
	}

	// Tenant domain (from DomainInfo already fetched by collectData → GetDomainInfo)
	if data.DomainInfo != nil && data.DomainInfo.ForestName != "" {
		data.AzureTenantDomain = data.DomainInfo.ForestName
	}

	// MFA registration report (modern endpoint)
	if mfaReport, err := azProvider.GetMFARegistrationReport(ctx); err == nil && mfaReport != nil {
		data.AzureMFACapableUsers = mfaReport.MFACapableUsers
		data.AzureMFARegisteredUsers = mfaReport.MFARegisteredUsers
	}

	// Post-collection enrichment: cross-reference SP names into OAuth2 grants and role assignments
	e.enrichAzureData(data)

	// v3.1.30 §3 — second-pass OAuth enrichment + summary build.
	// EnrichOAuth2Grants resolves clientName/resourceName via the SP cache,
	// parses Scope into Scopes[], flags dangerous scopes (Mail.*/Files.*/
	// Directory.*/RoleManagement.* etc). SummarizeOAuthGrants builds the
	// audit.oauthGrants payload. Idempotent — safe to call after enrichAzureData.
	if data.AzureOAuth2PermissionGrants != nil {
		EnrichOAuth2Grants(data.AzureOAuth2PermissionGrants, data.AzureServicePrincipals)
		data.AzureOAuthGrantsSummary = SummarizeOAuthGrants(data.AzureOAuth2PermissionGrants)
	}

	// v3.1.30 §4 — PIM detail collection. Schedules gives us active +
	// activated separately (assignmentType field), and ScheduleRequests
	// gives us 90 days of activation history. Both endpoints are
	// best-effort: a 403/PIM-not-configured tenant gets an empty payload
	// and the audit continues.
	pp, hasPIM := e.provider.(pimProvider)
	if hasPIM {
		schedules, _ := pp.GetRoleAssignmentSchedules(ctx)
		history, _ := pp.GetRoleAssignmentScheduleRequests(ctx, 90)
		// Eligible map from the already-merged AzureRoleAssignments slice
		// (avoids a second /roleEligibilityScheduleInstances call).
		eligibles := make(map[string]types.RoleAssignment)
		for _, ra := range data.AzureRoleAssignments {
			if !ra.IsEligible {
				continue
			}
			key := ra.PrincipalID + "|" + ra.RoleID + "|" + ra.DirectoryScopeID
			eligibles[key] = ra
		}
		data.AzurePIMActivationHistory = BuildPIMActivationHistorySummary(history)
		data.AzurePIMAssignments = BuildPIMAssignmentsSummary(schedules, eligibles, history)
	}

	// v3.1.30 §5 — cross-tenant access policy detail. Composes default +
	// per-partner config + multi-tenant-org. All three sources are
	// best-effort; the helper returns nil when none is populated so the
	// JSON output omits the audit.crossTenantAccess key entirely.
	if ctp, hasCT := e.provider.(crossTenantProvider); hasCT {
		def, _ := ctp.GetCrossTenantAccessPolicyDefault(ctx)
		partners, _ := ctp.GetCrossTenantAccessPolicyPartners(ctx)
		mto, _ := ctp.GetMultiTenantOrganization(ctx)
		data.AzureCrossTenantAccess = BuildCrossTenantAccessSummary(def, partners, mto)
	}

	// v3.1.30 §6 — auth methods detail (policy + strengths + per-user stats).
	// data.AzureAuthMethodsPolicy was already populated above by
	// GetAuthMethodsPolicy; we just add the strength + user-registration data
	// and let BuildAuthMethodsDetail compose the final payload.
	if amp, hasAMD := e.provider.(authMethodsDetailProvider); hasAMD {
		strengths, _ := amp.GetAuthenticationStrengthPolicies(ctx)
		userRegs, _ := amp.GetUserRegistrationDetails(ctx)
		data.AzureAuthMethodsDetail = BuildAuthMethodsDetail(
			data.AzureAuthMethodsPolicy,
			strengths,
			userRegs,
		)
	}

	// v3.1.36 — directory audits (90 days, 5 security categories). Same
	// sub-context budget pattern as sign-in logs (v3.1.32) so a slow Graph
	// response doesn't starve the rest of collection or the detection phase.
	// Default budget 5 min; configurable via opts.AzureDirectoryAuditsBudgetSeconds.
	// On budget timeout we keep partial events, mark truncated, emit warning.
	if alp, hasAuditLogs := e.provider.(auditLogsProvider); hasAuditLogs {
		days := opts.AzureDirectoryAuditsDays
		if days <= 0 {
			days = 90
		}
		maxN := opts.AzureDirectoryAuditsMax
		budget := time.Duration(opts.AzureDirectoryAuditsBudgetSeconds) * time.Second
		if budget <= 0 {
			budget = 5 * time.Minute
		}
		auditCtx, auditCancel := context.WithTimeout(ctx, budget)
		events, truncated, _, _, err := alp.GetDirectoryAudits(auditCtx, days, maxN)
		auditCancel()
		if err != nil {
			code := "AZURE_DIRECTORY_AUDITS_FAILED"
			msg := err.Error()
			if auditCtx.Err() == context.DeadlineExceeded && ctx.Err() == nil {
				code = "AZURE_DIRECTORY_AUDITS_TIMEOUT"
				msg = fmt.Sprintf("directory audits collection exceeded %s budget (collected %d events before timeout)", budget, len(events))
				truncated = true
			}
			data.Warnings = append(data.Warnings, types.Warning{
				Code:    code,
				Message: msg,
			})
		}
		// Always materialize whatever we got (partial counts on timeout).
		data.AzureDirectoryAudits = BuildDirectoryAuditsSummary(events, days, truncated)
	}

	// v3.1.37 §1 — Baseline Security Mode adoption.
	//
	// Two new policy snapshots first (best-effort, single-shot, no pagination).
	// Each is small (<2KB payload) so we don't need a sub-context budget —
	// 403/404 are silently skipped and the baseline helper marks the dependent
	// checks as "unknown". Goal: never have these endpoints starve the audit.
	if bpp, hasBaseline := e.provider.(baselinePoliciesProvider); hasBaseline {
		if pol, err := bpp.GetAuthorizationPolicy(ctx); err == nil {
			data.AzureAuthorizationPolicy = pol
		}
		if pol, err := bpp.GetAdminConsentRequestPolicy(ctx); err == nil {
			data.AzureAdminConsentRequestPolicy = pol
		}
	}

	// v3.1.38 §3 — Conditional Access policies (full nested detail).
	// Single-shot raw HTTP fetch (~200ms typical, ~30KB on a 14 policy
	// tenant). Best-effort: a 403 (missing Policy.Read.All) records a
	// warning and leaves the slice nil so the audit continues.
	//
	// MUST run before BuildBaselineSecuritySummary because the
	// BL_TOKEN_PROTECTION_ENABLED check reads the new detail slice
	// (the flat ConditionalAccessPolicy.TokenProtectionRequired field
	// is never populated by the SDK converter).
	if cap, hasCAP := e.provider.(caPoliciesDetailProvider); hasCAP {
		if details, err := cap.GetConditionalAccessPoliciesDetail(ctx); err != nil {
			data.Warnings = append(data.Warnings, types.Warning{
				Code:    "AZURE_CA_POLICIES_FAILED",
				Message: err.Error(),
			})
		} else {
			data.AzureConditionalAccessPolicyDetails = details
		}
	}

	// Pure post-collection derivation. Reads SecurityDefaults + CA policies +
	// AuthMethodsDetail.Policy + AuthorizationPolicy. No Graph roundtrip here.
	// version is the binary version embedded so an audit JSON traces back to
	// the exact baseline policy list it was checked against.
	data.AzureBaselineSecurity = BuildBaselineSecuritySummary(data, opts.CollectorVersion)

	// v3.1.39 §1 — Continuous Access Evaluation tenant rollup. Pure
	// post-collection derivation from AzureConditionalAccessPolicyDetails,
	// no extra Graph call. Lands at audit.cae for the SaaS analyzer.
	data.AzureCAESummary = BuildCAESummary(data, opts.CollectorVersion)

	// v3.1.39 §2 — Bookings / first-party orphan accounts rollup.
	// Pure post-collection derivation from data.Users (creationType +
	// UPN regex + cloud-only filter). Lands at audit.firstPartyAccounts.
	data.AzureFirstPartyAccounts = BuildFirstPartyAccountsSummary(data, opts.CollectorVersion)

	// v3.1.39 §3 — MFA registration policy rollup. Pure post-collection
	// derivation from AzureConditionalAccessPolicyDetails (filter on
	// userActions = urn:user:registersecurityinfo) cross-referenced with
	// AzureNamedLocations to determine trusted-location restriction.
	// Lands at audit.mfaRegistrationPolicy.
	data.AzureMFARegistrationPolicy = BuildMFARegistrationPolicySummary(data, opts.CollectorVersion)

	// v3.1.37 §2 — Entra Backup status probe. Single-shot, ~50ms when the
	// API is missing (fail-fast on HTTP 400). The provider always returns a
	// populated status object so the SaaS analyzer reads the same JSON
	// shape whether the API is GA or not — Available=false carries a
	// human-readable Reason, Available=true carries real config.
	if ebp, hasEntraBackup := e.provider.(entraBackupProvider); hasEntraBackup {
		if status, _ := ebp.GetEntraBackupStatus(ctx, opts.CollectorVersion); status != nil {
			data.AzureEntraBackup = status
		}
	}

	// v3.1.37 §3 — AI agent role assignments rollup (Silverfort Mar 2026
	// advisory). Pure derivation from AzureDirectoryRoles +
	// AzureRoleAssignments + AzureServicePrincipals (already in memory)
	// PLUS one Graph call per Group principal that holds an AI role
	// (typically 0-3 per audit). Each Group call is best-effort — a 403
	// returns nil and the helper surfaces the assignment without member
	// detail.
	{
		aiRoleIDs, _ := filterAIRoleIDs(data.AzureDirectoryRoles)
		groupMembers := make(map[string][]types.GroupMember)
		if len(aiRoleIDs) > 0 {
			if dge, hasGroupExpand := e.provider.(directoryGroupExpander); hasGroupExpand {
				for i := range data.AzureRoleAssignments {
					ra := &data.AzureRoleAssignments[i]
					if _, ok := aiRoleIDs[ra.RoleID]; !ok {
						continue
					}
					if !strings.EqualFold(ra.PrincipalType, "Group") {
						continue
					}
					if _, alreadyExpanded := groupMembers[ra.PrincipalID]; alreadyExpanded {
						continue
					}
					members, _, err := dge.GetGroupTransitiveMembers(ctx, ra.PrincipalID, 1000)
					if err != nil {
						// Surface as warning but keep going — the helper
						// will produce a partial summary.
						data.Warnings = append(data.Warnings, types.Warning{
							Code:    "AZURE_AI_AGENT_ROLES_PARTIAL",
							Message: "Failed to expand group " + ra.PrincipalID + " for AI agent role assignment: " + err.Error(),
						})
					}
					groupMembers[ra.PrincipalID] = members // nil entry on 403/404 → silent skip
				}
			}
		}
		data.AzureAIAgentRoles = BuildAIAgentRolesSummary(data, groupMembers, opts.CollectorVersion)
	}

	// v3.1.38 §1 — License ROI matrix payload. Probes 3 governance count
	// endpoints (best-effort, ~50ms each, fail-fast on 4xx) then derives
	// the audit.licenseInfo summary purely from already-collected data.
	if lip, hasLicenseInfo := e.provider.(licenseInfoProvider); hasLicenseInfo {
		// AccessReviews count — Probed flag distinguishes "endpoint
		// inaccessible" (Reason populated) from "endpoint probed and
		// returned 0" (genuine dormancy).
		if n, err := lip.GetAccessReviewDefinitionsCount(ctx); err == nil {
			data.AzureAccessReviewsCount = n
			data.AzureAccessReviewsProbed = true
		}
		if n, err := lip.GetEntitlementAccessPackagesCount(ctx); err == nil {
			data.AzureAccessPackagesCount = n
			data.AzureAccessPackagesProbed = true
		}
		if n, err := lip.GetVerifiedIDAuthoritiesCount(ctx); err == nil {
			data.AzureVerifiedIDIssuers = n
			data.AzureVerifiedIDProbed = true
		}
		if url, err := lip.GetOrganizationPrivacyStatementURL(ctx); err == nil {
			data.AzurePrivacyStatementURL = url
			data.AzurePrivacyStatementProbed = true
		}
		if n, err := lip.GetTermsOfUseAgreementsCount(ctx); err == nil {
			data.AzureTermsOfUseCount = n
			data.AzureTermsOfUseProbed = true
		}
	}
	data.AzureLicenseInfo = BuildLicenseInfoSummary(
		data,
		data.AzureAccessReviewsCount,
		data.AzureAccessPackagesCount,
		data.AzureVerifiedIDIssuers,
		time.Now().UTC(),
		opts.CollectorVersion,
	)

	// v3.1.38 §2 — Hybrid edges Entra ↔ AD. GetDevices in its own
	// sub-context budget (default 180s) so a 100k+ device tenant can't
	// starve the rest of collection. Best-effort: 403 returns nil and
	// the helper marks dependent fields with a Reason.
	if hlp, hasHybrid := e.provider.(hybridLinksProvider); hasHybrid {
		budget := time.Duration(opts.AzureHybridLinksBudgetSeconds) * time.Second
		if budget <= 0 {
			budget = 3 * time.Minute
		}
		hlCtx, hlCancel := context.WithTimeout(ctx, budget)
		devices, truncated, err := hlp.GetDevices(hlCtx, opts.AzureHybridLinksMax)
		hlCancel()
		if err != nil {
			code := "AZURE_HYBRID_LINKS_FAILED"
			msg := err.Error()
			if hlCtx.Err() == context.DeadlineExceeded && ctx.Err() == nil {
				code = "AZURE_HYBRID_LINKS_TIMEOUT"
				msg = fmt.Sprintf("hybrid devices collection exceeded %s budget (collected %d devices before timeout)", budget, len(devices))
				truncated = true
			}
			data.Warnings = append(data.Warnings, types.Warning{
				Code:    code,
				Message: msg,
			})
		}
		if devices != nil {
			data.AzureDevices = devices
			data.AzureDevicesTruncated = truncated
		}
	}
	data.AzureHybridLinks = BuildHybridLinksSummary(data, data.AzureDevicesTruncated, opts.CollectorVersion)
}

// enrichAzureData cross-references collected objects to fill in display names and additional fields.
func (e *Engine) enrichAzureData(data *DetectorData) {
	// Build SP lookup maps (id → SP, appId → SP)
	spByID := make(map[string]*types.ServicePrincipal, len(data.AzureServicePrincipals))
	spByAppID := make(map[string]*types.ServicePrincipal, len(data.AzureServicePrincipals))
	for i := range data.AzureServicePrincipals {
		sp := &data.AzureServicePrincipals[i]
		spByID[sp.ID] = sp
		if sp.AppID != "" {
			spByAppID[sp.AppID] = sp
		}
	}

	// Enrich OAuth2 permission grants with client and resource display names
	for i := range data.AzureOAuth2PermissionGrants {
		g := &data.AzureOAuth2PermissionGrants[i]
		if g.ClientName == "" {
			if sp, ok := spByID[g.ClientID]; ok {
				g.ClientName = sp.DisplayName
				g.ClientAppID = sp.AppID
			}
		}
		if g.ResourceName == "" {
			if sp, ok := spByID[g.ResourceID]; ok {
				g.ResourceName = sp.DisplayName
			}
		}
	}

	// Build risky user lookup for role assignment enrichment
	riskyByUPN := make(map[string]string, len(data.AzureRiskyUsers))
	for _, ru := range data.AzureRiskyUsers {
		if ru.UserPrincipalName != "" {
			riskyByUPN[ru.UserPrincipalName] = ru.RiskLevel
		}
	}

	// Build MFA/signIn lookup from Users slice (Azure users have these fields)
	type userInfo struct {
		lastSignIn    *time.Time
		mfaRegistered *bool
	}
	userInfoByUPN := make(map[string]userInfo, len(data.Users))
	for i := range data.Users {
		u := &data.Users[i]
		if u.UserPrincipalName == "" {
			continue
		}
		userInfoByUPN[u.UserPrincipalName] = userInfo{
			lastSignIn:    u.AzureLastSignInDateTime,
			mfaRegistered: u.AzureMfaRegistered,
		}
	}

	// Enrich role assignments with per-principal security posture
	for i := range data.AzureRoleAssignments {
		ra := &data.AzureRoleAssignments[i]
		upn := ra.UserPrincipalName
		if upn == "" {
			continue
		}
		if ui, ok := userInfoByUPN[upn]; ok {
			if ra.PrincipalType == "" {
				ra.PrincipalType = "User"
			}
			// Attach sign-in and MFA info to fields already on RoleAssignment
			_ = ui // consumed by azure_entities.go at conversion time via DetectorData
		}
		if riskLevel, ok := riskyByUPN[upn]; ok {
			_ = riskLevel // will be used in conversion
		}
	}

	// Enrich AppRegistrations: cross-link lastSignIn from associated SP
	appIDToLastSignIn := make(map[string]*time.Time)
	for i := range data.AzureServicePrincipals {
		sp := &data.AzureServicePrincipals[i]
		if sp.AppID != "" && sp.LastSignInDateTime != nil {
			appIDToLastSignIn[sp.AppID] = sp.LastSignInDateTime
		}
	}
	for i := range data.AzureAppRegistrations {
		app := &data.AzureAppRegistrations[i]
		if app.LastSignInDateTime == nil {
			if t, ok := appIDToLastSignIn[app.AppID]; ok {
				app.LastSignInDateTime = t
			}
		}
	}

	// Enrich AppRegistrations: merge delegated permissions from OAuth2PermissionGrants
	// into ApiPermissions. The current enrichAppRegistrations (client.go) only reads
	// requiredResourceAccess (the app manifest), which is a subset of what's actually
	// consented. The real consented permissions are in OAuth2PermissionGrants (delegated)
	// keyed by the service principal's ClientID.
	//
	// Build SP-ID → AppID map, then AppID → app index for fast lookup.
	spIDToAppID := make(map[string]string, len(data.AzureServicePrincipals))
	for i := range data.AzureServicePrincipals {
		sp := &data.AzureServicePrincipals[i]
		if sp.ID != "" && sp.AppID != "" {
			spIDToAppID[sp.ID] = sp.AppID
		}
	}
	appByAppID := make(map[string]int, len(data.AzureAppRegistrations))
	for i := range data.AzureAppRegistrations {
		if data.AzureAppRegistrations[i].AppID != "" {
			appByAppID[data.AzureAppRegistrations[i].AppID] = i
		}
	}

	// Build grant index: SP ID → scopes (from all OAuth2 grants)
	grantsBySPID := make(map[string][]string)
	for _, g := range data.AzureOAuth2PermissionGrants {
		for _, scope := range strings.Split(g.Scope, " ") {
			scope = strings.TrimSpace(scope)
			if scope != "" {
				grantsBySPID[g.ClientID] = append(grantsBySPID[g.ClientID], scope)
			}
		}
	}

	// Build AppID → SP ID reverse map (from SPs)
	appIDToSPID := make(map[string]string, len(data.AzureServicePrincipals))
	for i := range data.AzureServicePrincipals {
		sp := &data.AzureServicePrincipals[i]
		if sp.AppID != "" && sp.ID != "" {
			appIDToSPID[sp.AppID] = sp.ID
		}
	}

	// Also index grants by ClientAppID (enriched earlier from SP lookup)
	grantsByAppID := make(map[string][]string)
	for _, g := range data.AzureOAuth2PermissionGrants {
		if g.ClientAppID != "" {
			for _, scope := range strings.Split(g.Scope, " ") {
				scope = strings.TrimSpace(scope)
				if scope != "" {
					grantsByAppID[g.ClientAppID] = append(grantsByAppID[g.ClientAppID], scope)
				}
			}
		}
	}

	// For each AppRegistration, find grants via SP ID (primary) or AppID (fallback)
	delegatedPerms := make(map[int]map[string]bool)
	for i := range data.AzureAppRegistrations {
		app := &data.AzureAppRegistrations[i]
		var scopes []string

		// Primary path: App.AppID → SP.ID → grants by SP ID
		if spID, ok := appIDToSPID[app.AppID]; ok {
			scopes = grantsBySPID[spID]
		}
		// Fallback: grants indexed directly by ClientAppID
		if len(scopes) == 0 {
			scopes = grantsByAppID[app.AppID]
		}

		if len(scopes) == 0 {
			continue
		}
		if delegatedPerms[i] == nil {
			delegatedPerms[i] = make(map[string]bool)
		}
		for _, scope := range scopes {
			delegatedPerms[i][scope] = true
		}
	}

	// Merge into ApiPermissions (deduplicated)
	for idx, perms := range delegatedPerms {
		existing := make(map[string]bool, len(data.AzureAppRegistrations[idx].ApiPermissions))
		for _, p := range data.AzureAppRegistrations[idx].ApiPermissions {
			existing[p] = true
		}
		for p := range perms {
			if !existing[p] {
				data.AzureAppRegistrations[idx].ApiPermissions = append(data.AzureAppRegistrations[idx].ApiPermissions, p)
			}
		}
	}

	// v3.1.30 §7 — derive credential expiry buckets from existing EndDate
	// fields. Pure in-memory: spares every consumer (SaaS analyzer, reports,
	// dashboards, the 5 credential-* detectors) a redundant date subtraction.
	// Mutes apps + SPs in place to attach CredentialStatus per credential and
	// CredentialSummary per entity; the returned per-entity buckets feed the
	// tenant-wide CredentialExpiry summary that lands at audit.summary.
	now := time.Now().UTC()
	appsBucket := EnrichApplications(data.AzureAppRegistrations, now)
	spsBucket := EnrichServicePrincipals(data.AzureServicePrincipals, now)
	data.AzureCredentialExpiry = BuildCredentialExpirySummary(appsBucket, spsBucket)
}

// ReplMetadataProvider extends LDAPProvider with replication metadata queries
type ReplMetadataProvider interface {
	GetReplMetadata(ctx context.Context, dn string) ([]ReplMetadataEntry, error)
	GetReplValueMetadata(ctx context.Context, dn string) (map[string]time.Time, error)
}

// ReplMetadataEntry represents a single attribute's replication metadata
type ReplMetadataEntry struct {
	AttributeName  string
	LastChangeTime time.Time
	Version        int
}

// LDAPProvider is an extended provider interface for LDAP-specific queries
type LDAPProvider interface {
	providers.Provider
	GetGPOs(ctx context.Context, opts providers.QueryOptions) ([]types.GPO, error)
	GetOUs(ctx context.Context, opts providers.QueryOptions) ([]types.OU, error)
	GetGPOLinks(ctx context.Context) ([]GPOLink, error)
	GetGPOAcls(ctx context.Context, gpoDNs []string) ([]GPOAcl, error)
	GetTrusts(ctx context.Context, opts providers.QueryOptions) ([]types.Trust, error)
	GetCertTemplates(ctx context.Context, opts providers.QueryOptions) ([]types.CertTemplate, error)
	GetCertAuthorities(ctx context.Context) ([]types.CertAuthority, error) // v3.1.19 — ANSSI R36
	GetACLs(ctx context.Context, objectDNs []string) ([]types.ACLEntry, map[string]string, error)
	GetDNSZones(ctx context.Context) ([]types.DNSZone, error)
	GetFGPPs(ctx context.Context) ([]types.FGPP, error)
	GetSitesAndSubnets(ctx context.Context) ([]Site, []Subnet, error)
	// LookupBatch resolves ACL target DNs that aren't part of any typed
	// collection (containers, schema objects, AdminSDHolder, …) so detectors
	// can emit a typed AffectedEntity. Per-DN failures are silently skipped.
	LookupBatch(ctx context.Context, dns []string) ([]ObjectLookupEntry, error)
	// GetDCMetadata returns FSMO/site/RODC/replication metadata per DC.
	// Used by the v3.1.29 INFO_DOMAIN_CONTROLLER detector.
	GetDCMetadata(ctx context.Context, dcs []types.Computer) (map[string]*DCMetadata, error)
}

// pimProvider is the optional Azure-side interface that exposes the v3.1.30
// §4 PIM detail endpoints. Kept narrow on purpose so providers can implement
// it incrementally without touching the main AzureProvider interface.
type pimProvider interface {
	GetRoleAssignmentSchedules(ctx context.Context) ([]types.RoleAssignment, error)
	GetRoleAssignmentScheduleRequests(ctx context.Context, days int) ([]types.PIMScheduleRequest, error)
}

// crossTenantProvider — v3.1.30 §5. Same additive pattern as pimProvider:
// new methods exposed via type assertion in collectAzureData; mock providers
// keep compiling because they're not required to implement this.
type crossTenantProvider interface {
	GetCrossTenantAccessPolicyDefault(ctx context.Context) (*types.CrossTenantDefaultPolicy, error)
	GetCrossTenantAccessPolicyPartners(ctx context.Context) ([]types.CrossTenantPartnerPolicy, error)
	GetMultiTenantOrganization(ctx context.Context) (*types.CrossTenantMultiTenantOrg, error)
}

// authMethodsDetailProvider — v3.1.30 §6. Same additive pattern. The existing
// GetAuthMethodsPolicy stays on the main AzureProvider interface (consumed by
// 5 detectors); only the new strength + per-user methods are gated here so
// mock providers can opt-in incrementally.
type authMethodsDetailProvider interface {
	GetAuthenticationStrengthPolicies(ctx context.Context) ([]types.AuthStrengthPolicy, error)
	GetUserRegistrationDetails(ctx context.Context) ([]types.UserRegistrationDetail, error)
}

// auditLogsProvider — v3.1.36. Optional Azure provider extension for the
// directory audit logs endpoint (90 days, 5 security categories). Type-
// asserted in collectAzureData so mock providers stay valid without
// implementing it.
type auditLogsProvider interface {
	GetDirectoryAudits(ctx context.Context, days, maxResults int) ([]types.DirectoryAudit, bool, time.Time, time.Time, error)
}

// baselinePoliciesProvider — v3.1.37 §1. Optional Azure provider extension
// for the two new policy endpoints needed by the Microsoft Baseline
// Security Mode adoption check (audit.baselineSecurity). Both calls are
// single-shot, best-effort: a 403/404 returns nil,nil and the baseline
// helper marks the dependent checks as "unknown".
type baselinePoliciesProvider interface {
	GetAuthorizationPolicy(ctx context.Context) (*types.AuthorizationPolicy, error)
	GetAdminConsentRequestPolicy(ctx context.Context) (*types.AdminConsentRequestPolicy, error)
}

// entraBackupProvider — v3.1.37 §2. Optional Azure provider extension for
// the Entra Backup & Recovery status probe. Single-shot, never returns a
// hard error: the underlying call always returns a populated status object
// (real data on HTTP 200, fallback Available=false on any 4xx/network
// failure) so the audit pipeline keeps moving.
type entraBackupProvider interface {
	GetEntraBackupStatus(ctx context.Context, collectorVersion string) (*types.EntraBackupStatus, error)
}

// directoryGroupExpander — v3.1.37 §3. Optional Azure provider extension
// for resolving a Group's transitive members. Used to count actual humans
// reachable via groups assigned to AI agent admin roles. Best-effort: a
// 403 (missing Group.Read.All) returns nil,false,nil and the helper
// surfaces the assignment without member detail.
type directoryGroupExpander interface {
	GetGroupTransitiveMembers(ctx context.Context, groupID string, maxN int) ([]types.GroupMember, bool, error)
}

// licenseInfoProvider — v3.1.38 §1. Optional Azure provider extension for
// the License ROI matrix data sources. GetSubscribedSkus replaces the
// data-shedding GetLicenseTier on the collection path (the legacy method
// stays available for backwards compat, but the engine now calls
// GetSubscribedSkus once and derives the tier via DeriveLicenseTier so
// /subscribedSkus is hit only once per audit). The 3 governance counters
// are best-effort single-shot probes that return 0 on 4xx.
type licenseInfoProvider interface {
	GetSubscribedSkus(ctx context.Context) ([]types.SubscribedSku, error)
	GetAccessReviewDefinitionsCount(ctx context.Context) (int, error)
	GetEntitlementAccessPackagesCount(ctx context.Context) (int, error)
	GetVerifiedIDAuthoritiesCount(ctx context.Context) (int, error)
	// T_058 (B_158) — governance probes feeding AZ_NO_PRIVACY_STATEMENT and
	// AZ_NO_TERMS_OF_USE. Same best-effort shape as the three counts above.
	GetOrganizationPrivacyStatementURL(ctx context.Context) (string, error)
	GetTermsOfUseAgreementsCount(ctx context.Context) (int, error)
}

// hybridLinksProvider — v3.1.38 §2. Optional Azure provider extension for
// the Hybrid edges Entra ↔ AD payload. GetDevices is paginated and
// best-effort: a 403 (missing Device.Read.All) returns (nil, false, nil)
// and the helper marks the dependent fields with a Reason. Paginated
// behind a sub-context budget so a 100k+ device tenant can't starve the
// rest of the audit.
type hybridLinksProvider interface {
	GetDevices(ctx context.Context, maxN int) ([]types.AzureDevice, bool, error)
}

// caPoliciesDetailProvider — v3.1.38 §3. Optional Azure provider extension
// that exposes the full nested Microsoft Graph shape for every Conditional
// Access policy. The SDK-backed GetConditionalAccessPolicies stays in place
// for in-collector detectors (flat type), this raw-HTTP fetch preserves
// every field — sessionControls.tokenProtection.isEnabled,
// signInFrequency.isEnabled, persistentBrowser.isEnabled, applicationEnforced
// Restrictions, continuousAccessEvaluation, secureSignInSession,
// disableResilienceDefaults, grantControls.authenticationStrength,
// authenticationFlows, includeUserActions, ... — so the SaaS analyzer can
// compute per-control adoption %. Best-effort: a 403 (missing Policy.Read.All)
// emits AZURE_CA_POLICIES_FAILED and the slice stays nil.
type caPoliciesDetailProvider interface {
	GetConditionalAccessPoliciesDetail(ctx context.Context) ([]types.ConditionalAccessPolicyDetail, error)
}

// AzureProvider is an extended provider interface for Azure AD / Entra ID queries
type AzureProvider interface {
	providers.Provider
	GetConditionalAccessPolicies(ctx context.Context) ([]types.ConditionalAccessPolicy, error)
	GetDirectoryRoles(ctx context.Context) ([]types.DirectoryRole, error)
	GetRoleAssignments(ctx context.Context) ([]types.RoleAssignment, error)
	GetAppRegistrations(ctx context.Context, opts providers.QueryOptions) ([]types.AppRegistration, error)
	GetServicePrincipals(ctx context.Context, opts providers.QueryOptions) ([]types.ServicePrincipal, error)
	GetOAuth2PermissionGrants(ctx context.Context) ([]types.OAuth2PermissionGrant, error)
	GetAuthMethodsPolicy(ctx context.Context) (*types.AuthMethodsPolicy, error)
	GetNamedLocations(ctx context.Context) ([]types.NamedLocation, error)
	GetRiskyUsers(ctx context.Context) ([]types.RiskyUser, error)
	GetRiskySignIns(ctx context.Context) ([]types.RiskySignIn, error)
	GetSecurityDefaults(ctx context.Context) (*types.TenantSecurityDefaults, error)
	GetTenantConfig(ctx context.Context) (*types.AzureTenantConfig, error)
	GetLicenseTier(ctx context.Context) string
	GetMFARegistrationReport(ctx context.Context) (*azure.MFARegistrationReport, error)
	// GetSignInLogs (v3.1.30 §1) fetches the last `days` days of /beta/auditLogs/signIns.
	// Returns the events, a truncation flag (hit maxResults before
	// @odata.nextLink == nil), and the timestamp of the oldest event in
	// the slice (so the SaaS knows the real lookback window).
	GetSignInLogs(ctx context.Context, days, maxResults int) ([]types.SignInLog, bool, time.Time, error)
}

// enrichACLFlags scans ACLEntries and sets boolean ACL flags on Computer objects.
// Used by COMPUTER_ACL_ABUSE and COMPUTER_DCSYNC_RIGHTS detectors.
//
// For computers: sets DangerousACL when a non-self entity has GenericAll/WriteDACL/WriteOwner
// on the computer object (making the computer vulnerable to takeover).
// Sets ReplicationRights when the computer has DCSync rights on the domain root.
//
// Note: User ACL flags (HasWriteDACL, HasGenericAll, HasWriteOwner, HasDCSyncRights)
// are no longer set here — attack path detection for users is handled entirely by
// the BFS attack graph (ACL_ABUSE, DCSYNC path types).
func enrichACLFlags(data *DetectorData) {
	if len(data.ACLEntries) == 0 {
		return
	}

	// Build computer index by SID (trustee lookup)
	computerBySID := make(map[string]int, len(data.Computers))
	for i := range data.Computers {
		if data.Computers[i].ObjectSID != "" {
			computerBySID[data.Computers[i].ObjectSID] = i
		}
	}

	// Build computer index by DN (target lookup for DangerousACL)
	computerByDN := make(map[string]int, len(data.Computers))
	for i := range data.Computers {
		computerByDN[strings.ToLower(data.Computers[i].DN)] = i
	}

	// Domain root DN (for DCSync detection)
	var domainDN string
	if data.DomainInfo != nil {
		domainDN = strings.ToLower(data.DomainInfo.DomainDN)
		if domainDN == "" {
			domainDN = strings.ToLower(data.DomainInfo.DN)
		}
	}

	// Build set of privileged SIDs (trustees that are EXPECTED to have dangerous ACLs).
	// Domain Admins, Enterprise Admins, etc. having GenericAll on objects is normal.
	// We skip these as trustees for Computer.DangerousACL to avoid false positives.
	privilegedSIDs := make(map[string]bool)
	for _, g := range data.Groups {
		if g.AdminCount || g.ObjectSID != "" {
			for suffix := range types.PrivilegedSIDSuffixes {
				if strings.HasSuffix(g.ObjectSID, suffix) {
					privilegedSIDs[g.ObjectSID] = true
				}
			}
			if g.AdminCount {
				privilegedSIDs[g.ObjectSID] = true
			}
		}
	}
	for _, u := range data.Users {
		if u.AdminCount && u.ObjectSID != "" {
			privilegedSIDs[u.ObjectSID] = true
		}
	}
	// Well-known SIDs that are expected to have full control
	privilegedSIDs["S-1-5-18"] = true // SYSTEM
	privilegedSIDs["S-1-3-0"] = true  // Creator Owner
	privilegedSIDs["S-1-5-10"] = true // SELF

	for _, acl := range data.ACLEntries {
		if !strings.Contains(acl.AceType, "ALLOWED") {
			continue
		}

		objectDNLower := strings.ToLower(acl.ObjectDN)
		mask := acl.AccessMask
		objectType := strings.ToLower(acl.ObjectType)

		// --- Computer DangerousACL: non-privileged entity has dangerous rights ON the computer ---
		// Skip self-ACLs and expected admin ACLs (Domain Admins, SYSTEM, etc.)
		if idx, ok := computerByDN[objectDNLower]; ok {
			if data.Computers[idx].ObjectSID != acl.Trustee && !privilegedSIDs[acl.Trustee] {
				if mask&types.MaskGenericAll != 0 || mask&types.MaskWriteDACL != 0 || mask&types.MaskWriteOwner != 0 {
					data.Computers[idx].DangerousACL = true
				}
			}
		}

		// --- DCSync rights on domain root: computer as TRUSTEE ---
		if domainDN != "" && objectDNLower == domainDN {
			if mask&types.MaskControlAccess != 0 {
				isDCSync := objectType == strings.ToLower(types.GUIDDSReplicationGetChanges) ||
					objectType == strings.ToLower(types.GUIDDSReplicationGetChangesAll)
				if isDCSync {
					if idx, ok := computerBySID[acl.Trustee]; ok {
						data.Computers[idx].ReplicationRights = true
					}
				}
			}
		}
	}
}

// Detector platforms, derived from the package layout convention
// internal/audit/detectors/<platform>/... Mirrors catalog.PlatformOf, which
// classifies the same way for the vulnerability catalogs; it lives in
// internal/audit/catalog, which imports this package, so the engine cannot
// import it back without a cycle.
const (
	platformAD    = "ad"
	platformAzure = "azure"
)

// detectorPlatformOf returns the platform a detector belongs to, or "" when it
// does not live under internal/audit/detectors/<platform>/ (in-package test
// detectors, future core detectors). Unclassified detectors are never gated.
func detectorPlatformOf(d Detector) string {
	t := reflect.TypeOf(d)
	if t == nil {
		return ""
	}
	for t.Kind() == reflect.Ptr {
		t = t.Elem()
	}
	const prefix = "github.com/etcsec-com/etc-collector/internal/audit/detectors/"
	rest := strings.TrimPrefix(t.PkgPath(), prefix)
	if rest == t.PkgPath() { // prefix absent — not a platform detector
		return ""
	}
	if i := strings.IndexByte(rest, '/'); i > 0 {
		return rest[:i]
	}
	return rest
}

// providerGate is the set of detector platforms whose data the bound provider
// actually collects. A nil/empty gate is disabled (allows everything).
type providerGate map[string]bool

// allows reports whether a detector may run for the audited provider.
// Fail-open by construction: a disabled gate or an unclassified detector is
// always allowed. Only a detector that positively belongs to another
// platform is dropped.
func (g providerGate) allows(d Detector) bool {
	if len(g) == 0 {
		return true
	}
	p := detectorPlatformOf(d)
	if p == "" {
		return true
	}
	return g[p]
}

// providerGate builds the platform gate from the provider currently bound to
// the engine. The provider type is the primary signal; the collection
// capability interfaces are also probed so a hybrid provider that really does
// collect both on-prem and Entra data unlocks both platforms and a combined
// AD+Entra audit still runs every detector.
//
// Returns nil (gate disabled) when there is no provider or when the provider
// cannot be classified — an unknown provider must not silently empty the
// detector set.
func (e *Engine) providerGate() providerGate {
	if e.provider == nil {
		return nil
	}
	gate := make(providerGate, 2)
	switch e.provider.Type() {
	case providers.ProviderTypeLDAP:
		gate[platformAD] = true
	case providers.ProviderTypeAzure:
		gate[platformAzure] = true
	case providers.ProviderTypeIntune, providers.ProviderTypeExchange, providers.ProviderTypeGoogle:
		// Same layout convention — detectors/<provider type>/... — for the
		// platforms that have a detector tree but no detectors yet.
		gate[string(e.provider.Type())] = true
	}
	if _, ok := e.provider.(LDAPProvider); ok {
		gate[platformAD] = true
	}
	if _, ok := e.provider.(AzureProvider); ok {
		gate[platformAzure] = true
	}
	if len(gate) == 0 {
		return nil
	}
	return gate
}

// selectDetectors returns the detectors to run based on options.
//
// Selection order: provider gate ∩ [(Categories ∪ DetectorIDs) − ExcludeCategories
// − ExcludeDetectors]. Empty include set means "every detector of the audited
// platform". Excludes always win.
func (e *Engine) selectDetectors(opts RunOptions) []Detector {
	// Build the include set as IDs for set semantics.
	include := make(map[string]Detector)

	// Every detector — AD and Entra alike — is compiled into the same binary
	// and self-registers into one global registry via init(). Without this
	// gate an on-prem AD audit also runs the Entra detectors (and vice-versa).
	// Most of those are "absence of config = finding" checks, so on a run
	// where the corresponding data was never collected they can only ever be
	// false positives (T_019: 69 Entra types / 719 findings / 7% of the score
	// on the DC01 AD baseline). See providerGate for the fail-open rules.
	//
	// The gate intersects EVERY selection path, including DetectorIDs. It is
	// tempting to let an explicitly named ID override it, but Scope.ApplyTo
	// materialises every --scope-* form (profiles, include-categories, even a
	// lone --scope-exclude-detectors) into RunOptions.DetectorIDs, so such an
	// exemption would silently reopen the bug for every scoped audit.
	// Selection semantics are unchanged within the audited platform.
	gate := e.providerGate()

	if len(opts.DetectorIDs) > 0 {
		for _, id := range opts.DetectorIDs {
			if d, ok := e.registry.Get(id); ok && gate.allows(d) {
				include[d.ID()] = d
			}
		}
	}
	if len(opts.Categories) > 0 {
		catSet := make(map[DetectorCategory]bool, len(opts.Categories))
		for _, cat := range opts.Categories {
			catSet[cat] = true
		}
		for _, d := range e.registry.All() {
			// Category selection is intersected with the gate, not exempted
			// from it: "groups" is a category on both platforms, so
			// --scope-include-categories groups on an AD audit means the AD
			// groups detectors.
			if catSet[d.Category()] && gate.allows(d) {
				include[d.ID()] = d
			}
		}
	}
	if len(opts.DetectorIDs) == 0 && len(opts.Categories) == 0 {
		for _, d := range e.registry.All() {
			if gate.allows(d) {
				include[d.ID()] = d
			}
		}
	}

	// Subtract ExcludeCategories.
	if len(opts.ExcludeCategories) > 0 {
		excludeCats := make(map[DetectorCategory]bool, len(opts.ExcludeCategories))
		for _, cat := range opts.ExcludeCategories {
			excludeCats[cat] = true
		}
		for id, d := range include {
			if excludeCats[d.Category()] {
				delete(include, id)
			}
		}
	}

	// Subtract ExcludeDetectors (last word).
	for _, id := range opts.ExcludeDetectors {
		delete(include, id)
	}

	detectors := make([]Detector, 0, len(include))
	for _, d := range include {
		detectors = append(detectors, d)
	}
	return detectors
}

// runSequential runs detectors one by one
func (e *Engine) runSequential(ctx context.Context, detectors []Detector, data *DetectorData, cfg *exclusions.Config, dryRun bool) []types.Finding {
	var findings []types.Finding
	for _, d := range detectors {
		select {
		case <-ctx.Done():
			return findings
		default:
			view := e.dataForDetector(data, d.ID(), cfg, dryRun)
			results := d.Detect(ctx, view)
			findings = append(findings, results...)
		}
	}
	return findings
}

// runParallel runs detectors concurrently
func (e *Engine) runParallel(ctx context.Context, detectors []Detector, data *DetectorData, cfg *exclusions.Config, dryRun bool) []types.Finding {
	var (
		mu       sync.Mutex
		findings []types.Finding
		wg       sync.WaitGroup
	)

	for _, d := range detectors {
		wg.Add(1)
		go func(detector Detector) {
			defer wg.Done()
			select {
			case <-ctx.Done():
				return
			default:
				view := e.dataForDetector(data, detector.ID(), cfg, dryRun)
				results := detector.Detect(ctx, view)
				mu.Lock()
				findings = append(findings, results...)
				mu.Unlock()
			}
		}(d)
	}

	wg.Wait()
	return findings
}

// dataForDetector returns the DetectorData snapshot the given detector should
// see. If no per-detector rule matches detectorID, the original data is
// returned unchanged. Otherwise a shallow-copied DetectorData with filtered
// Users/Computers/Groups/OUs slices is returned (other fields shared — they
// don't contain assets identified by the rule).
//
// In dryRun mode, matches are still recorded in ExclusionReport so the
// auditor sees what would be excluded, but the detector receives the
// unfiltered original data so findings reflect the unfiltered state.
//
// Records any matched DetectorExclusion entries on data.ExclusionReport in a
// thread-safe way so runParallel can write to it.
func (e *Engine) dataForDetector(data *DetectorData, detectorID string, cfg *exclusions.Config, dryRun bool) *DetectorData {
	if cfg == nil || cfg.IsEmpty() {
		return data
	}
	users, computers, groups, ous, excl := exclusions.ApplyPerDetector(cfg, detectorID, data)
	if len(excl) == 0 {
		return data
	}
	// Persist matched exclusions so they end up in the final report.
	if data.ExclusionReport != nil {
		e.mu.Lock()
		data.ExclusionReport.PerDetector = append(data.ExclusionReport.PerDetector, excl...)
		e.mu.Unlock()
	}
	if dryRun {
		return data
	}
	clone := *data
	clone.Users = users
	clone.Computers = computers
	clone.Groups = groups
	clone.OUs = ous
	return &clone
}

// shadowData wraps *DetectorData with no-op Set* methods for dry-run
// exclusion computation. Get* methods are inherited from *DetectorData.
type shadowData struct{ *DetectorData }

// SetUsers is a no-op in dry-run mode.
func (shadowData) SetUsers([]types.User) {}

// SetGroups is a no-op in dry-run mode.
func (shadowData) SetGroups([]types.Group) {}

// SetComputers is a no-op in dry-run mode.
func (shadowData) SetComputers([]types.Computer) {}

// SetOUs is a no-op in dry-run mode.
func (shadowData) SetOUs([]types.OU) {}

// exclusionsToExport converts an internal exclusions.Report to the
// serialisable AuditResult.Exclusions struct.
func exclusionsToExport(r *exclusions.Report) *types.ExclusionReport {
	if r == nil {
		return nil
	}
	out := &types.ExclusionReport{
		RulesHash:    r.RulesHash,
		RulesVersion: r.RulesVersion,
	}
	if len(r.AssetCounts) > 0 {
		out.AssetCounts = make(map[string]*types.ExclusionCounts, len(r.AssetCounts))
		for k, v := range r.AssetCounts {
			counts := &types.ExclusionCounts{
				Total:    v.Total,
				Scanned:  v.Scanned,
				Excluded: v.Excluded,
			}
			for _, rr := range v.Reasons {
				counts.Reasons = append(counts.Reasons, types.ExclusionReason{
					Field:     rr.Field,
					Pattern:   rr.Pattern,
					Matched:   rr.Matched,
					SampleDNs: append([]string(nil), rr.SampleDNs...),
				})
			}
			out.AssetCounts[k] = counts
		}
	}
	for _, d := range r.PerDetector {
		out.PerDetector = append(out.PerDetector, types.ExclusionPerDetector{
			DetectorID: d.DetectorID,
			Reason:     d.Reason,
			Scope:      d.Scope,
			Matched:    d.Matched,
			SampleDNs:  append([]string(nil), d.SampleDNs...),
		})
	}
	return out
}

// calculateStats calculates audit statistics
func (e *Engine) calculateStats(findings []types.Finding, data *DetectorData) *types.AuditStatistics {
	stats := types.NewAuditStatistics()
	// T_036 / B_039 — this is the number of finding RECORDS, `info` included.
	// It is the same quantity ConvertToTSFormat publishes as
	// summary.risk.findings.records; the report's `total` is a different unit
	// (affected objects, `info` excluded). Keep the two in step: they are the
	// two halves of one definition, not two competing ones.
	stats.TotalFindings = len(findings)
	stats.UsersScanned = len(data.Users)
	// T_031 — the report summary used to hard-code users_disabled to 0. This is
	// the only place that holds the collected user list, so the real split is
	// computed here and carried through AuditStatistics.
	for _, u := range data.Users {
		if u.Disabled {
			stats.UsersDisabled++
		}
	}
	stats.UsersEnabled = stats.UsersScanned - stats.UsersDisabled
	stats.GroupsScanned = len(data.Groups)
	stats.ComputersScanned = len(data.Computers)
	stats.OUsScanned = len(data.OUs)

	for _, f := range findings {
		stats.BySeverity[f.Severity]++
		stats.ByCategory[f.Category]++
	}

	// Azure-specific counts (populated when Azure data is present)
	if len(data.AzureAppRegistrations) > 0 || len(data.AzureServicePrincipals) > 0 || len(data.AzureConditionalAccessPolicies) > 0 {
		stats.Applications = len(data.AzureAppRegistrations)
		stats.ServicePrincipals = len(data.AzureServicePrincipals)
		stats.ConditionalAccessPolicies = len(data.AzureConditionalAccessPolicies)

		for _, ca := range data.AzureConditionalAccessPolicies {
			if ca.State == "enabled" {
				stats.CAPoliciesEnabled++
			} else {
				stats.CAPoliciesDisabled++
			}
		}

		// Guest count
		for _, u := range data.Users {
			if u.AzureUserType != nil && *u.AzureUserType == "Guest" {
				stats.GuestUsers++
			}
		}

		// PIM: eligible (non-permanent) role assignments
		for _, ra := range data.AzureRoleAssignments {
			if ra.IsEligible {
				stats.PIMEligibleRoles++
			}
		}
		stats.PIMEnabled = stats.PIMEligibleRoles > 0

		// Identity Protection
		if len(data.AzureRiskyUsers) > 0 || len(data.AzureRiskySignIns) > 0 {
			stats.IdentityProtectionEnabled = true
			riskyUsers := len(data.AzureRiskyUsers)
			riskySignIns := len(data.AzureRiskySignIns)
			stats.RiskyUsersCount = &riskyUsers
			stats.RiskySignInsCount = &riskySignIns
		}

		// MFA counts — prefer the modern userRegistrationDetails report if available
		if data.AzureMFACapableUsers > 0 || data.AzureMFARegisteredUsers > 0 {
			stats.MFACapableUsers = data.AzureMFACapableUsers
			stats.MFAEnforcedUsers = data.AzureMFARegisteredUsers
			nonGuest := stats.UsersScanned - stats.GuestUsers
			if nonGuest > stats.MFACapableUsers {
				stats.MFANotConfiguredUsers = nonGuest - stats.MFACapableUsers
			}
		} else {
			// Fallback: derive from per-user AzureMfaRegistered field
			for _, u := range data.Users {
				if u.AzureUserType != nil && *u.AzureUserType == "Guest" {
					continue
				}
				if u.AzureMfaRegistered != nil && *u.AzureMfaRegistered {
					stats.MFACapableUsers++
				} else {
					stats.MFANotConfiguredUsers++
				}
			}
		}

		stats.LicenseType = data.AzureLicenseTier
		stats.TenantDomain = data.AzureTenantDomain
	}

	return stats
}

// buildSummary creates a summary of findings by type
func (e *Engine) buildSummary(findings []types.Finding) []types.FindingSummary {
	byType := make(map[string]*types.FindingSummary)

	for _, f := range findings {
		if _, ok := byType[f.Type]; !ok {
			byType[f.Type] = &types.FindingSummary{
				Type:     f.Type,
				Severity: f.Severity,
				Count:    0,
			}
		}
		byType[f.Type].Count += f.Count
	}

	// Sorted by Type (T_046/B_048): byType is a map, so ranging it directly
	// gives a randomized order per process — same input, different JSON,
	// different sha256 across runs (the same class of bug the sort in Run()
	// fixes for the findings array itself).
	sortedTypes := make([]string, 0, len(byType))
	for t := range byType {
		sortedTypes = append(sortedTypes, t)
	}
	sort.Strings(sortedTypes)

	summary := make([]types.FindingSummary, 0, len(byType))
	for _, t := range sortedTypes {
		summary = append(summary, *byType[t])
	}

	return summary
}

// collectReplMetadata collects replication metadata for temporal change detectors.
func (e *Engine) collectReplMetadata(ctx context.Context, rp ReplMetadataProvider, data *DetectorData) {
	baseDN := data.DomainInfo.DomainDN
	configDN := "CN=Configuration," + baseDN
	schemaDN := "CN=Schema," + configDN

	// 1. Schema security descriptor last changed (SI000047)
	meta, err := rp.GetReplMetadata(ctx, schemaDN)
	if err == nil {
		for _, m := range meta {
			if strings.EqualFold(m.AttributeName, "nTSecurityDescriptor") {
				data.SchemaSDLastChanged = m.LastChangeTime
				break
			}
		}
	}

	// 2. Display Specifier changes in last 90 days (SI000082)
	displaySpecDN := "CN=DisplaySpecifiers," + configDN
	// We need to use the provider's search to list display specifier containers, then check each
	// Since we can't call search directly from here, we check sub-containers via GetReplMetadata
	// on the DisplaySpecifiers container itself. But PK checks individual display specifier objects.
	// Approach: query the display specifier locale containers (e.g., CN=409,CN=DisplaySpecifiers,...)
	// and for each, check if any attribute was modified recently.
	localeCNs := []string{"409", "407", "40C", "411", "412", "804", "C0A"} // EN, DE, FR, JA, KO, ZH, ES
	cutoff90 := time.Now().AddDate(0, 0, -90)
	for _, locale := range localeCNs {
		localeDN := "CN=" + locale + "," + displaySpecDN
		localeMeta, err := rp.GetReplMetadata(ctx, localeDN)
		if err != nil {
			continue
		}
		for _, m := range localeMeta {
			if !m.LastChangeTime.IsZero() && m.LastChangeTime.After(cutoff90) {
				data.DisplaySpecifierChanges = append(data.DisplaySpecifierChanges, localeDN)
				break // one change is enough to flag this locale container
			}
		}
	}

	// 3. Privileged group membership changes in last 7 days (SI000043)
	privilegedGroupRIDs := []string{"-512", "-519", "-518", "-516", "-498"}
	domainSID := data.DomainInfo.DomainSID
	data.PrivilegedGroupMemberChanges = make(map[string]map[string]time.Time)

	for _, group := range data.Groups {
		isPrivileged := false
		for _, rid := range privilegedGroupRIDs {
			if strings.HasSuffix(group.ObjectSID, rid) {
				isPrivileged = true
				break
			}
		}
		if !isPrivileged && domainSID != "" {
			// Also check Enterprise Admins (RID 519) and Schema Admins (RID 518) which may be from root domain
			_ = domainSID
		}
		if !isPrivileged {
			continue
		}

		dn := group.DN
		if dn == "" {
			dn = group.DistinguishedName
		}
		if dn == "" {
			continue
		}

		memberChanges, err := rp.GetReplValueMetadata(ctx, dn)
		if err != nil || len(memberChanges) == 0 {
			continue
		}
		data.PrivilegedGroupMemberChanges[dn] = memberChanges
	}
}
