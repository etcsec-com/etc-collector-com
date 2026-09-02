// Package types defines common types used across the application
package types

import (
	"time"
)

// AuditResponse is the top-level response structure (matches TypeScript)
type AuditResponse struct {
	Success  bool         `json:"success"`
	Provider string       `json:"provider"`
	Audit    *AuditReport `json:"audit"`
	Warnings []Warning    `json:"warnings,omitempty"`

	// v3.1.19 — Integrity is the SHA-256 of the canonical JSON form of this
	// AuditResponse with Integrity itself zeroed out. Lets an ANSSI auditor
	// prove the report wasn't modified post-audit (no secret involved —
	// reproduces the hash via `etc-collector audit verify <file>`).
	Integrity *IntegritySignature `json:"integrity,omitempty"`
}

// IntegritySignature carries the hash + spec required to recompute it.
type IntegritySignature struct {
	Algorithm  string    `json:"algorithm"` // "sha256-canonical-json"
	Hash       string    `json:"hash"`      // hex SHA-256
	ComputedAt time.Time `json:"computedAt"`
	Spec       string    `json:"spec"` // verification recipe
}

// AuditReport is the main audit structure (matches TypeScript audit object)
type AuditReport struct {
	Accounts       *AccountsSection     `json:"accounts"`
	Computers      *FindingsSection     `json:"computers"`
	Groups         *FindingsSection     `json:"groups"`
	Security       *SecuritySection     `json:"security"`
	Permissions    *FindingsSection     `json:"permissions"`
	ADCS           *FindingsSection     `json:"adcs"`
	GPOSecurity    *FindingsSection     `json:"gpoSecurity"`
	TrustsAnalysis *FindingsSection     `json:"trustsAnalysis"`
	DomainConfig   *DomainConfigSection `json:"domainConfig"`
	Temporal       *FindingsSection     `json:"temporal"`
	AttackGraph    *AttackGraphExport   `json:"attackGraph,omitempty"`
	ExtendedConfig *FindingsSection     `json:"extendedConfig"`
	Summary        *SummarySection      `json:"summary"`
	Metadata       *MetadataSection     `json:"metadata"`

	// v3.1.30 §1 — Azure sign-in logs deep collection. Top-level keys
	// `audit.signInLogs[]` (mode=raw) or `audit.signInLogsAggregated`
	// (mode=aggregated). Truncation transparency fields are surfaced
	// regardless so the SaaS knows the real lookback window.
	SignInLogs                []SignInLog           `json:"signInLogs,omitempty"`
	SignInLogsAggregated      *SignInLogsAggregated `json:"signInLogsAggregated,omitempty"`
	SignInLogsTruncated       bool                  `json:"signInLogsTruncated,omitempty"`
	SignInLogsEventsCollected int                   `json:"signInLogsEventsCollected,omitempty"`
	SignInLogsOldestCollected *time.Time            `json:"signInLogsOldestCollected,omitempty"`
	SignInLogsRequestedDays   int                   `json:"signInLogsRequestedDays,omitempty"`
	SignInLogsActualDays      int                   `json:"signInLogsActualDays,omitempty"`

	// v3.1.30 §3 — Azure OAuth grants + service principals top-level keys
	// for ConsentFix detection / SP inventory. Keys land at
	// audit.oauthGrants and audit.servicePrincipals respectively.
	OAuthGrants       *OAuthGrantsSummary `json:"oauthGrants,omitempty"`
	ServicePrincipals []ServicePrincipal  `json:"servicePrincipals,omitempty"`

	// v3.1.30 §4 — PIM detail. Keys land at audit.pimAssignments (active +
	// eligible + neverActivated) and audit.pimActivationHistory (90-day
	// schedule requests with justifications and ticket refs).
	PIMAssignments       *PIMAssignmentsSummary       `json:"pimAssignments,omitempty"`
	PIMActivationHistory *PIMActivationHistorySummary `json:"pimActivationHistory,omitempty"`

	// v3.1.30 §5 — cross-tenant access policy detail. Lands at
	// audit.crossTenantAccess (default + partners[] + multiTenantOrganization).
	CrossTenantAccess *CrossTenantAccessSummary `json:"crossTenantAccess,omitempty"`

	// v3.1.30 §6 — auth methods detail. Lands at
	// audit.authenticationMethodsDetail (policy + strengthPolicies + userRegistrationStats).
	AuthenticationMethodsDetail *AuthMethodsDetail `json:"authenticationMethodsDetail,omitempty"`

	// v3.1.30 §7 — App registrations top-level slice (mirror of §3
	// servicePrincipals). Each AppRegistration carries CredentialSummary;
	// each cred inside carries CredentialStatus. Lands at audit.applications.
	// The tenant-wide rollup goes under audit.summary.credentialExpiry below.
	Applications []AppRegistration `json:"applications,omitempty"`

	// v3.1.36 — Directory audit logs (last 90d, 5 security categories).
	// Powers the SaaS Identity Drift Timeline. Lands at audit.directoryAudits.
	DirectoryAudits *DirectoryAuditsSummary `json:"directoryAudits,omitempty"`

	// v3.1.37 §1 — Microsoft Baseline Security Mode adoption rollup.
	// Lands at audit.baselineSecurity. Powers KPI #20.
	BaselineSecurity *BaselineSecuritySummary `json:"baselineSecurity,omitempty"`

	// v3.1.37 §2 — Microsoft Entra Backup & Recovery status. Lands at
	// audit.entraBackup. Powers KPI #21.
	EntraBackup *EntraBackupStatus `json:"entraBackup,omitempty"`

	// v3.1.37 §3 — AI agent role assignments rollup. Lands at
	// audit.aiAgentRoles. Powers KPI #26.
	AIAgentRoles *AIAgentRolesSummary `json:"aiAgentRoles,omitempty"`

	// v3.1.38 §1 — License ROI matrix. Lands at audit.licenseInfo.
	// Powers KPI #12.
	LicenseInfo *LicenseInfoSummary `json:"licenseInfo,omitempty"`

	// v3.1.38 §2 — Hybrid edges Entra ↔ AD. Lands at audit.hybridLinks.
	// Powers KPI #17.
	HybridLinks *HybridLinksSummary `json:"hybridLinks,omitempty"`

	// v3.1.38 §3 — Conditional Access policies (full nested detail). Lands
	// at audit.conditionalAccessPolicies. Powers KPI #22 (Token Protection
	// adoption %) + KPI #14 (CA coverage matrix).
	ConditionalAccessPolicies []ConditionalAccessPolicyDetail `json:"conditionalAccessPolicies,omitempty"`

	// v3.1.39 §1 — Continuous Access Evaluation tenant rollup. Lands at
	// audit.cae. Powers KPI #23.
	CAE *CAESummary `json:"cae,omitempty"`

	// v3.1.39 §2 — Bookings / first-party orphan accounts rollup. Lands
	// at audit.firstPartyAccounts. Powers KPI #25.
	FirstPartyAccounts *FirstPartyAccountsSummary `json:"firstPartyAccounts,omitempty"`

	// v3.1.39 §3 — MFA registration CA policy rollup. Lands at
	// audit.mfaRegistrationPolicy. Powers KPI #27.
	MFARegistrationPolicy *MFARegistrationPolicySummary `json:"mfaRegistrationPolicy,omitempty"`
}

// AccountsSection groups account-related findings
type AccountsSection struct {
	Status     *FindingsSection `json:"status"`
	Privileged *FindingsSection `json:"privileged"`
	Dangerous  *FindingsSection `json:"dangerous"`
	Service    *FindingsSection `json:"service"`
}

// SecuritySection groups security-related findings
type SecuritySection struct {
	Passwords *FindingsSection `json:"passwords"`
	Kerberos  *FindingsSection `json:"kerberos"`
	Advanced  *FindingsSection `json:"advanced"`
}

// FindingsSection contains findings and total count
type FindingsSection struct {
	Findings []Finding `json:"findings"`
	Total    int       `json:"total"`
}

// DomainConfigSection contains domain configuration info
type DomainConfigSection struct {
	DomainInfo     *DomainInfo     `json:"domainInfo,omitempty"`
	PasswordPolicy *PasswordPolicy `json:"passwordPolicy,omitempty"`
	KerberosPolicy *KerberosPolicy `json:"kerberosPolicy,omitempty"`
	GPOSummary     *GPOSummary     `json:"gpoSummary,omitempty"`
	Trusts         []Trust         `json:"trusts,omitempty"`
}

// PasswordPolicy represents domain password policy
type PasswordPolicy struct {
	MinLength            int  `json:"minLength"`
	MaxAge               int  `json:"maxAge"`
	MinAge               int  `json:"minAge"`
	HistoryCount         int  `json:"historyCount"`
	ComplexityEnabled    bool `json:"complexityEnabled"`
	ReversibleEncryption bool `json:"reversibleEncryption"`
	LockoutThreshold     int  `json:"lockoutThreshold"`
	LockoutDuration      int  `json:"lockoutDuration"`
}

// KerberosPolicy represents domain Kerberos policy
type KerberosPolicy struct {
	MaxTicketAge  int `json:"maxTicketAge"`
	MaxRenewAge   int `json:"maxRenewAge"`
	MaxServiceAge int `json:"maxServiceAge"`
	MaxClockSkew  int `json:"maxClockSkew"`
}

// GPOSummary contains GPO statistics
type GPOSummary struct {
	Total    int `json:"total"`
	Linked   int `json:"linked"`
	Unlinked int `json:"unlinked"`
	Disabled int `json:"disabled"`
}

// SummarySection contains audit summary
type SummarySection struct {
	Objects          *ObjectsSummary  `json:"objects"`
	Risk             *RiskSummary     `json:"risk"`
	ComplianceScores []FrameworkScore `json:"complianceScores,omitempty"`
	// Exclusions surfaces any asset/detector filters applied to this run,
	// including the rulesHash so external auditors can verify config integrity.
	Exclusions *ExclusionReport `json:"exclusions,omitempty"`

	// v3.1.30 §7 — tenant-wide credential expiry rollup (apps + SPs entity
	// counts per bucket). Lands at audit.summary.credentialExpiry. Powers
	// the SaaS Executive Tab "App Credential Expiration Cliff" widget.
	CredentialExpiry *CredentialExpirySummary `json:"credentialExpiry,omitempty"`
}

// FrameworkScore is the per-framework compliance summary embedded in
// SummarySection.ComplianceScores. Populated by audit/compliance.CalculatePerFramework.
//
// Score is 0-100, higher is better (= % of automated-control checks that pass).
// Rating maps the score to one of: excellent | low | medium | high | critical
// (where "low" = low risk = good, mirroring the global risk rating semantics).
//
// Score formula : passed / (total - manual - notApplicable) * 100
// (manual and not_applicable controls are excluded from the denominator so a
// dashboard can show a meaningful score without being penalized by controls
// the collector cannot verify).
//
// EvaluatedControls is the per-control breakdown using the official catalog
// for the framework (PA-099 R-codes, NIST AC/AU/IA codes, etc.). Each entry
// states whether the control passed, failed, requires manual verification,
// or is not_applicable in this environment.
//
// MaturityAxes is populated for ANSSI_PA099 only (5-axis composite score
// inspired by the ANSSI maturity index for AD).
type FrameworkScore struct {
	Framework             string             `json:"framework"`
	Score                 float64            `json:"score"`
	Rating                string             `json:"rating"`
	ControlsTotal         int                `json:"controlsTotal"`
	ControlsPassed        int                `json:"controlsPassed"`
	ControlsFailed        int                `json:"controlsFailed"`
	ControlsManual        int                `json:"controlsManual,omitempty"`
	ControlsNotApplicable int                `json:"controlsNotApplicable,omitempty"`
	EvaluatedControls     []EvaluatedControl `json:"evaluatedControls,omitempty"`
	FailedControls        []string           `json:"failedControls,omitempty"` // kept for backward compatibility
	MaturityAxes          []MaturityAxis     `json:"maturityAxes,omitempty"`
}

// EvaluatedControl is the per-control checklist entry used by
// FrameworkScore.EvaluatedControls. It enables consumers to render the
// framework as a complete reference checklist (passed/failed/manual/n.a.)
// rather than just a list of failures.
//
// All user-facing string fields (Title, Section, Rationale) are in English
// for product alignment, regardless of the source publication's original
// language.
type EvaluatedControl struct {
	// Code is the official control identifier (e.g. "R8" for PA-099,
	// "M14" for Guide d'hygiène, "AC-2" for NIST 800-53,
	// "Art.21(2)(a)" for NIS2, "5.1.4" for HDS, "V-73305" for DISA STIG).
	Code string `json:"code"`

	// Title is the official English title of the control.
	Title string `json:"title"`

	// OfficialFR is the original French title from the source PDF, kept
	// byte-for-byte. Populated for ANSSI catalogs (PA-099, BP-039, Guide
	// d'hygiène). Empty for English-source frameworks (CIS, NIST, DISA).
	// v3.1.20 — added so SaaS UI can render the official French title for
	// francophone users without translating server-side.
	OfficialFR string `json:"officialFR,omitempty"`

	// Section is the chapter/section name from the source publication
	// (English). Used for grouping in dashboards.
	Section string `json:"section,omitempty"`

	// Status is one of: passed | failed | manual | not_applicable.
	Status string `json:"status"`

	// Severity is the worst severity from triggered findings, when Status
	// is "failed". Empty otherwise.
	Severity string `json:"severity,omitempty"`

	// FindingTypes lists the detector IDs that emitted at least one finding
	// covering this control. Used for drilldown UI.
	FindingTypes []string `json:"findingTypes,omitempty"`

	// ManualOnly is true when the control is organisational, contractual,
	// physical, or otherwise not auditable from LDAP/SYSVOL/registry/Graph.
	// In that case Status is "manual".
	ManualOnly bool `json:"manualOnly,omitempty"`

	// Rationale is a short English explanation. Set when:
	//   - ManualOnly == true (why automation is not possible)
	//   - Status == "not_applicable" (why the control does not apply here)
	Rationale string `json:"rationale,omitempty"`
}

// MaturityAxis is a single dimension of the ANSSI AD maturity index.
// Level is 0 (absent) to 5 (excellent), computed from the % of controls
// in the axis that are failing.
type MaturityAxis struct {
	Name           string   `json:"name"`
	Level          int      `json:"level"`              // 0..5
	Coverage       float64  `json:"coverage"`           // % controls passing in this axis
	Controls       []string `json:"controls,omitempty"` // control IDs included
	FailedControls []string `json:"failedControls,omitempty"`
}

// ObjectsSummary contains scanned object counts
type ObjectsSummary struct {
	Users         int `json:"users"`
	UsersEnabled  int `json:"users_enabled"`
	UsersDisabled int `json:"users_disabled"`
	Groups        int `json:"groups"`
	OUs           int `json:"ous,omitempty"`
	Computers     int `json:"computers,omitempty"`
	// Azure-specific (omitted for AD audits)
	Guests                    int    `json:"guests,omitempty"`
	Applications              int    `json:"applications,omitempty"`
	ServicePrincipals         int    `json:"service_principals,omitempty"`
	ConditionalAccessPolicies int    `json:"conditional_access_policies,omitempty"`
	CAPoliciesEnabled         int    `json:"ca_policies_enabled,omitempty"`
	CAPoliciesDisabled        int    `json:"ca_policies_disabled,omitempty"`
	PIMEnabled                *bool  `json:"pim_enabled,omitempty"`
	PIMEligibleRoles          int    `json:"total_pim_roles,omitempty"`
	IdentityProtectionEnabled *bool  `json:"identity_protection_enabled,omitempty"`
	RiskyUsersCount           *int   `json:"risky_users_count,omitempty"`
	RiskySignInsCount         *int   `json:"risky_sign_ins_count,omitempty"`
	MFAEnforcedUsers          int    `json:"mfa_enforced_users,omitempty"`
	MFACapableUsers           int    `json:"mfa_capable_users,omitempty"`
	MFANotConfiguredUsers     int    `json:"mfa_not_configured_users,omitempty"`
	LicenseType               string `json:"license_type,omitempty"`
	TenantDomain              string `json:"tenant_domain,omitempty"`
}

// RiskSummary contains risk assessment
type RiskSummary struct {
	Score    float64          `json:"score"`
	Rating   string           `json:"rating"`
	Findings *FindingsSummary `json:"findings"`
}

// FindingsSummary contains finding counts by severity.
//
// Units matter here, and they were the subject of B_039 (see ConvertToTSFormat):
//
//   - Critical/High/Medium/Low/Info and Total are sums of each finding's Count,
//     i.e. numbers of AFFECTED OBJECTS. Total excludes Info, for backwards
//     compatibility with the consumers that already read it.
//   - Records is the number of FINDING RECORDS the audit produced, Info
//     included — the quantity engine.go computes as len(findings) and which was
//     previously not exported anywhere.
//
// Both are published so the report can never again disagree with itself about
// what "a finding" means.
type FindingsSummary struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	// Info is the affected-object count for informational findings (domain and
	// OU inventories, mostly). It was missing entirely, so 364 records were
	// invisible in the summary on DC01 — counted apart rather than dropped.
	Info           int `json:"info"`
	Total          int `json:"total"`
	TotalInstances int `json:"totalInstances"`
	// Records is the number of finding records, Info included.
	Records int `json:"records"`
}

// MetadataSection contains audit execution metadata
type MetadataSection struct {
	Provider  string             `json:"provider"`
	Domain    *DomainMetadata    `json:"domain"`
	Options   *OptionsMetadata   `json:"options"`
	Execution *ExecutionMetadata `json:"execution"`
}

// DomainMetadata contains domain connection info
type DomainMetadata struct {
	Name    string `json:"name"`
	BaseDN  string `json:"baseDN"`
	LDAPUrl string `json:"ldapUrl"`
}

// OptionsMetadata contains audit options
type OptionsMetadata struct {
	IncludeDetails   bool `json:"includeDetails"`
	IncludeComputers bool `json:"includeComputers"`
	IncludeConfig    bool `json:"includeConfig"`
}

// ExecutionMetadata contains execution timing
type ExecutionMetadata struct {
	Timestamp time.Time `json:"timestamp"`
	Duration  string    `json:"duration"`
}

// NewFindingsSection creates a new FindingsSection
func NewFindingsSection() *FindingsSection {
	return &FindingsSection{
		Findings: []Finding{},
		Total:    0,
	}
}

// AddFinding adds a finding to the section
func (fs *FindingsSection) AddFinding(f Finding) {
	fs.Findings = append(fs.Findings, f)
	fs.Total += f.Count
}

// categoryMapping maps Go categories to TS structure paths
var categoryMapping = map[string]string{
	"accounts":     "accounts.status",
	"privileged":   "accounts.privileged",
	"dangerous":    "accounts.dangerous",
	"service":      "accounts.service",
	"computers":    "computers",
	"groups":       "groups",
	"kerberos":     "security.kerberos",
	"password":     "security.passwords",
	"advanced":     "security.advanced",
	"permissions":  "permissions",
	"adcs":         "adcs",
	"gpo":          "gpoSecurity",
	"trusts":       "trustsAnalysis",
	"compliance":   "extendedConfig",
	"attack-paths": "attackGraph",
	"network":      "domainConfig",
	"monitoring":   "temporal",
}

// annotateDisabledAccounts records, on the finding itself, how many of its
// affected accounts cannot authenticate (T_031 / DET_4), and returns those
// same two numbers so the caller can also feed them into scoring (T_057 /
// B_165 — see the call site in ConvertToTSFormat).
//
// On DC01, 176 of the critical account entities are disabled accounts spread
// over 11 detectors. The per-entity `enabled` flag already said so, but only to
// someone who opened all of them: a consultant reading "PASSWORD_NOT_REQUIRED —
// 23 accounts, critical" had no way to see that all 23 are disabled.
//
// The arbitration is MARK, not downgrade, and not drop:
//   - dropping them would create a blind spot — a disabled account with
//     GenericAll on the domain is a live risk the moment it is re-enabled,
//     which is the mirror image of the false positives T_024 removed;
//   - downgrading the DISPLAYED severity here would desynchronise the report
//     from the score if the score were computed independently, upstream, from
//     the original severities — exactly the class of contradiction this
//     function exists to prevent. T_057 closes the other half of that same
//     contradiction: leaving the score computed from the RAW counts, ignoring
//     what this function already knows, disagreed with the report in the
//     opposite direction (a "Critical, 293 accounts" finding scored as if 293
//     live accounts were exposed, when the entities right here say otherwise).
//     Severity/labels stay untouched; only the score's own arithmetic changes,
//     via the returned counts — see ConvertToTSFormat.
//
// Marking is applied to every finding rather than to a hand-picked list of
// detectors, so a new detector cannot silently miss it.
func annotateDisabledAccounts(f *Finding) (disabled, accounts int) {
	if len(f.AffectedEntities) == 0 {
		return 0, 0
	}
	for _, e := range f.AffectedEntities {
		if e.Type != "user" && e.Type != "computer" {
			continue
		}
		accounts++
		if !e.Enabled {
			disabled++
		}
	}
	if disabled == 0 {
		return disabled, accounts
	}
	if f.Details == nil {
		f.Details = make(map[string]interface{})
	}
	f.Details["disabledAccounts"] = disabled
	f.Details["affectedAccounts"] = accounts
	if disabled == accounts {
		f.Details["disabledAccountsNote"] = "every affected account is disabled and cannot authenticate today; the exposure applies if any is re-enabled"
	} else {
		f.Details["disabledAccountsNote"] = "some affected accounts are disabled and cannot authenticate today; prioritise the enabled ones"
	}
	return disabled, accounts
}

// ConvertToTSFormat converts an AuditResult to TypeScript-compatible AuditResponse
func ConvertToTSFormat(result *AuditResult, provider string, ldapURL string, baseDN string, includeDetails bool) *AuditResponse {
	report := &AuditReport{
		Accounts: &AccountsSection{
			Status:     NewFindingsSection(),
			Privileged: NewFindingsSection(),
			Dangerous:  NewFindingsSection(),
			Service:    NewFindingsSection(),
		},
		Computers: NewFindingsSection(),
		Groups:    NewFindingsSection(),
		Security: &SecuritySection{
			Passwords: NewFindingsSection(),
			Kerberos:  NewFindingsSection(),
			Advanced:  NewFindingsSection(),
		},
		Permissions:    NewFindingsSection(),
		ADCS:           NewFindingsSection(),
		GPOSecurity:    NewFindingsSection(),
		TrustsAnalysis: NewFindingsSection(),
		Temporal:       NewFindingsSection(),
		ExtendedConfig: NewFindingsSection(),
		DomainConfig:   &DomainConfigSection{},
		AttackGraph:    result.AttackGraph,
	}

	// Distribute findings to appropriate sections
	var totalInstances int
	severityCounts := make(map[Severity]int)

	// T_057 / B_165 — scoreFindings mirrors result.Findings exactly (same
	// Type/Severity/Category, same length and order) except Count, which
	// drops the disabled share of that finding's account entities. It is
	// used ONLY to recompute the score below; every displayed field (the `f`
	// routed into report sections a few lines down, including its ORIGINAL
	// Count and full AffectedEntities) is untouched, so nothing a reader
	// sees changes — this is scoring input, not a report edit. See
	// CalculateScore's call below for why a finding can still contribute
	// zero to the score while remaining fully visible in the report.
	scoreFindings := make([]Finding, 0, len(result.Findings))

	for _, f := range result.Findings {
		severityCounts[f.Severity] += f.Count
		totalInstances += f.Count
		if f.TotalInstances > 0 {
			totalInstances += f.TotalInstances - f.Count
		}

		disabled, _ := annotateDisabledAccounts(&f)

		scored := f
		scored.Count = f.Count - disabled
		if scored.Count < 0 {
			// disabled counts entities in AffectedEntities; f.Count is a
			// separately-set aggregate that D6-verified equal to
			// len(AffectedEntities) on every DC01 critical/high finding, but
			// that equality isn't a guaranteed invariant everywhere (e.g. a
			// capped entity list) — floor at 0 rather than let a detector
			// where it doesn't hold inflate the score with a negative count.
			scored.Count = 0
		}
		scoreFindings = append(scoreFindings, scored)

		// Route finding to appropriate section based on category
		switch f.Category {
		case "accounts":
			// Sub-categorize accounts based on finding type
			if isPrivilegedFinding(f.Type) {
				report.Accounts.Privileged.AddFinding(f)
			} else if isDangerousFinding(f.Type) {
				report.Accounts.Dangerous.AddFinding(f)
			} else if isServiceFinding(f.Type) {
				report.Accounts.Service.AddFinding(f)
			} else {
				report.Accounts.Status.AddFinding(f)
			}
		case "computers":
			report.Computers.AddFinding(f)
		case "groups":
			report.Groups.AddFinding(f)
		case "kerberos":
			report.Security.Kerberos.AddFinding(f)
		case "password":
			report.Security.Passwords.AddFinding(f)
		case "advanced":
			report.Security.Advanced.AddFinding(f)
		case "permissions":
			report.Permissions.AddFinding(f)
		case "adcs":
			report.ADCS.AddFinding(f)
		case "gpo":
			report.GPOSecurity.AddFinding(f)
		case "trusts":
			report.TrustsAnalysis.AddFinding(f)
		case "compliance":
			report.ExtendedConfig.AddFinding(f)
		case "attack-paths":
			report.Security.Advanced.AddFinding(f)
		case "network":
			report.Security.Advanced.AddFinding(f)
		case "monitoring":
			report.Temporal.AddFinding(f)
		default:
			// Default to extendedConfig for unknown categories
			report.ExtendedConfig.AddFinding(f)
		}
	}

	// Build summary.
	//
	// T_036 / B_039 — the repository used to carry two different "totals" that
	// nobody could reconcile, and neither of them counted findings:
	//
	//   engine.go   stats.TotalFindings = len(findings)  → 559 finding RECORDS
	//                                                      (364 of them `info`),
	//                                                      never exported at all;
	//   response.go critical+high+medium+low             → 2610, the SUM of the
	//                                                      per-finding Count, i.e.
	//                                                      AFFECTED OBJECTS, and
	//                                                      the only one published.
	//
	// The gap on DC01 is 2051, not the 365 `info` findings one would expect,
	// because the two quantities are in different units. Anyone recounting the
	// JSON by hand produced a third number.
	//
	// The single definition kept is: **a finding is one detected defect record;
	// its Count is how many objects that defect affects.** Both quantities are
	// now published side by side under names that say which is which, and the
	// `info` severity — 364 records that were silently absent — has its own
	// bucket instead of being dropped from `total` without a trace.
	//
	// `Total` keeps its historical meaning (objects affected, `info` excluded)
	// so existing consumers do not break; `Info` and `Records` are additions.
	totalFindings := severityCounts[SeverityCritical] + severityCounts[SeverityHigh] +
		severityCounts[SeverityMedium] + severityCounts[SeverityLow]

	// T_031 — both fields used to be fabricated here: users_enabled was the
	// full scanned count and users_disabled a hard-coded 0, so the summary
	// announced "0 disabled" on a domain where 519 of 546 accounts are
	// disabled. They now carry the real split computed at collection time.
	objects := &ObjectsSummary{
		Users:         result.Statistics.UsersScanned,
		UsersEnabled:  result.Statistics.UsersEnabled,
		UsersDisabled: result.Statistics.UsersDisabled,
		Groups:        result.Statistics.GroupsScanned,
	}

	if provider == "azure" {
		objects.Guests = result.Statistics.GuestUsers
		objects.Applications = result.Statistics.Applications
		objects.ServicePrincipals = result.Statistics.ServicePrincipals
		objects.ConditionalAccessPolicies = result.Statistics.ConditionalAccessPolicies
		objects.CAPoliciesEnabled = result.Statistics.CAPoliciesEnabled
		objects.CAPoliciesDisabled = result.Statistics.CAPoliciesDisabled
		pimEnabled := result.Statistics.PIMEnabled
		objects.PIMEnabled = &pimEnabled
		objects.PIMEligibleRoles = result.Statistics.PIMEligibleRoles
		ipEnabled := result.Statistics.IdentityProtectionEnabled
		objects.IdentityProtectionEnabled = &ipEnabled
		objects.RiskyUsersCount = result.Statistics.RiskyUsersCount
		objects.RiskySignInsCount = result.Statistics.RiskySignInsCount
		objects.MFAEnforcedUsers = result.Statistics.MFAEnforcedUsers
		objects.MFACapableUsers = result.Statistics.MFACapableUsers
		objects.MFANotConfiguredUsers = result.Statistics.MFANotConfiguredUsers
		objects.LicenseType = result.Statistics.LicenseType
		objects.TenantDomain = result.Statistics.TenantDomain
		// T_031 — Azure carried the same defect plus an internal contradiction:
		// users_enabled was "scanned minus guests" (a guest/member split, not an
		// enabled/disabled one) while users_disabled was a hard-coded 0, so the
		// two never summed to the total. The Graph collector does populate
		// User.Disabled (providers/azure/client.go:3535), so both fields now use
		// the same real split as the AD path; the guest count stays available on
		// its own field, objects.Guests.
		objects.UsersEnabled = result.Statistics.UsersEnabled
		objects.UsersDisabled = result.Statistics.UsersDisabled
	} else {
		objects.OUs = result.Statistics.OUsScanned
		objects.Computers = result.Statistics.ComputersScanned
	}

	// T_057 / B_165 — score, recomputed from scoreFindings rather than
	// carried over from result.Score.
	//
	// Where the original score is computed (engine.go:214, inside
	// Engine.Run) is BEFORE this function ever runs: types.CalculateScore is
	// called on the raw findings the moment detection finishes, using each
	// finding's full Count with no visibility into which of its
	// AffectedEntities are disabled — annotateDisabledAccounts (which knows
	// that) doesn't run until here, inside ConvertToTSFormat, one JSON-encode
	// away from the client. On DC01, 1109 of 1359 (81.6%) critical/high
	// account entities are disabled — accounts that cannot authenticate
	// today — yet every one of them weighed on the score exactly as heavily
	// as a live account.
	//
	// Fix is ORDER, not detection (the ticket's framing): recompute the same
	// CalculateScore formula, in the same place the report is otherwise
	// finalised, over scoreFindings — Count minus each finding's disabled
	// share, everything else identical. Chosen over the other two options in
	// the ticket: full exclusion, not a reduced weight, because the score is
	// meant to read as CURRENT exposure and a disabled account contributes
	// none — it cannot be used right now, full stop. That is not the same
	// claim as "downgrade the severity", which is what the comment on
	// annotateDisabledAccounts (and T_057's own acceptance criteria) forbids:
	// the displayed Count, AffectedEntities and Severity above are the
	// ORIGINAL result.Findings, byte-for-byte — a disabled account with
	// GenericAll on the domain still shows as a full Critical/High finding,
	// exactly as before, so nobody loses the "this becomes a live risk the
	// moment it's re-enabled" signal the original design protected. Only the
	// score's own arithmetic, over a copy, changes.
	riskScore, _ := CalculateScore(scoreFindings,
		result.Statistics.UsersScanned, result.Statistics.ComputersScanned, result.Statistics.GroupsScanned)
	riskRating := CalculateRating(riskScore)

	report.Summary = &SummarySection{
		Objects: objects,
		Risk: &RiskSummary{
			Score:  riskScore,
			Rating: riskRating,
			Findings: &FindingsSummary{
				Critical:       severityCounts[SeverityCritical],
				High:           severityCounts[SeverityHigh],
				Medium:         severityCounts[SeverityMedium],
				Low:            severityCounts[SeverityLow],
				Info:           severityCounts[SeverityInfo],
				Total:          totalFindings,
				TotalInstances: totalInstances,
				Records:        len(result.Findings),
			},
		},
		ComplianceScores: result.ComplianceScores,
		Exclusions:       result.Exclusions,
	}

	// Build metadata
	report.Metadata = &MetadataSection{
		Provider: provider,
		Domain: &DomainMetadata{
			Name:    result.Domain,
			BaseDN:  baseDN,
			LDAPUrl: ldapURL,
		},
		Options: &OptionsMetadata{
			IncludeDetails:   includeDetails,
			IncludeComputers: true,
			IncludeConfig:    true,
		},
		Execution: &ExecutionMetadata{
			Timestamp: result.Timestamp,
			Duration:  result.Duration.String(),
		},
	}

	// Populate domainConfig with domain info, password policy, and Kerberos policy
	if result.DomainInfo != nil {
		report.DomainConfig.DomainInfo = result.DomainInfo
		report.DomainConfig.PasswordPolicy = &PasswordPolicy{
			MinLength:            result.DomainInfo.MinPasswordLength,
			MaxAge:               result.DomainInfo.MaxPasswordAge,
			MinAge:               result.DomainInfo.MinPwdAge,
			HistoryCount:         result.DomainInfo.PasswordHistoryLength,
			ComplexityEnabled:    true,
			ReversibleEncryption: false,
			LockoutThreshold:     result.DomainInfo.LockoutThreshold,
			LockoutDuration:      result.DomainInfo.LockoutDuration,
		}
		report.DomainConfig.KerberosPolicy = &KerberosPolicy{
			MaxTicketAge:  result.DomainInfo.MaxTicketAge,
			MaxRenewAge:   result.DomainInfo.MaxRenewAge,
			MaxServiceAge: 600,
			MaxClockSkew:  5,
		}
	}

	resp := &AuditResponse{
		Success:  true,
		Provider: provider,
		Audit:    report,
	}

	// Propagate warnings from audit result
	if len(result.Warnings) > 0 {
		resp.Warnings = result.Warnings
	}

	// v3.1.30 §1 — Azure sign-in logs: forward from AuditResult to the
	// top-level audit.signInLogs[] / audit.signInLogsAggregated keys plus
	// the truncation transparency fields.
	if result.SignInLogs != nil {
		report.SignInLogs = result.SignInLogs
	}
	if result.SignInLogsAggregated != nil {
		report.SignInLogsAggregated = result.SignInLogsAggregated
	}
	report.SignInLogsTruncated = result.SignInLogsTruncated
	report.SignInLogsEventsCollected = result.SignInLogsEventsCollected
	report.SignInLogsOldestCollected = result.SignInLogsOldestCollected
	report.SignInLogsRequestedDays = result.SignInLogsRequestedDays
	report.SignInLogsActualDays = result.SignInLogsActualDays

	// v3.1.30 §3 — forward OAuth grants + SP detail to the audit report.
	if result.OAuthGrants != nil {
		report.OAuthGrants = result.OAuthGrants
	}
	if len(result.ServicePrincipals) > 0 {
		report.ServicePrincipals = result.ServicePrincipals
	}

	// v3.1.30 §4 — forward PIM summaries.
	if result.PIMAssignments != nil {
		report.PIMAssignments = result.PIMAssignments
	}
	if result.PIMActivationHistory != nil {
		report.PIMActivationHistory = result.PIMActivationHistory
	}

	// v3.1.30 §5 — forward cross-tenant access summary.
	if result.CrossTenantAccess != nil {
		report.CrossTenantAccess = result.CrossTenantAccess
	}

	// v3.1.30 §6 — forward auth methods detail.
	if result.AuthenticationMethodsDetail != nil {
		report.AuthenticationMethodsDetail = result.AuthenticationMethodsDetail
	}

	// v3.1.30 §7 — forward apps top-level (mirror §3 SPs) and the
	// tenant-wide credential expiry rollup nested under summary.
	if len(result.Applications) > 0 {
		report.Applications = result.Applications
	}
	if result.CredentialExpiry != nil && report.Summary != nil {
		report.Summary.CredentialExpiry = result.CredentialExpiry
	}

	// v3.1.36 — forward directory audits (90d, 5 security categories).
	if result.DirectoryAudits != nil {
		report.DirectoryAudits = result.DirectoryAudits
	}

	// v3.1.37 §1 — forward Baseline Security Mode adoption rollup.
	if result.BaselineSecurity != nil {
		report.BaselineSecurity = result.BaselineSecurity
	}

	// v3.1.37 §2 — forward Entra Backup status probe.
	if result.EntraBackup != nil {
		report.EntraBackup = result.EntraBackup
	}

	// v3.1.37 §3 — forward AI agent role assignments rollup.
	if result.AIAgentRoles != nil {
		report.AIAgentRoles = result.AIAgentRoles
	}

	// v3.1.38 §1 — forward License ROI matrix.
	if result.LicenseInfo != nil {
		report.LicenseInfo = result.LicenseInfo
	}

	// v3.1.38 §2 — forward Hybrid edges Entra ↔ AD.
	if result.HybridLinks != nil {
		report.HybridLinks = result.HybridLinks
	}

	// v3.1.38 §3 — forward Conditional Access policies (full nested detail).
	if result.ConditionalAccessPolicies != nil {
		report.ConditionalAccessPolicies = result.ConditionalAccessPolicies
	}

	// v3.1.39 §1 — forward CAE tenant rollup.
	if result.CAE != nil {
		report.CAE = result.CAE
	}

	// v3.1.39 §2 — forward Bookings / first-party orphan accounts rollup.
	if result.FirstPartyAccounts != nil {
		report.FirstPartyAccounts = result.FirstPartyAccounts
	}

	// v3.1.39 §3 — forward MFA registration policy rollup.
	if result.MFARegistrationPolicy != nil {
		report.MFARegistrationPolicy = result.MFARegistrationPolicy
	}

	return resp
}

// isPrivilegedFinding checks if a finding type relates to privileged accounts
func isPrivilegedFinding(findingType string) bool {
	privilegedTypes := map[string]bool{
		"SENSITIVE_DELEGATION":          true,
		"DOMAIN_ADMIN_IN_DESCRIPTION":   true,
		"NOT_IN_PROTECTED_USERS":        true,
		"ADMIN_NO_SMARTCARD":            true,
		"ADMIN_ASREP_ROASTABLE":         true,
		"ADMIN_LOGON_COUNT_LOW":         true,
		"ADMIN_COUNT_ORPHANED":          true,
		"PRIVILEGED_ACCOUNT_SPN":        true,
		"EXCESSIVE_PRIVILEGED_ACCOUNTS": true,
	}
	return privilegedTypes[findingType]
}

// isDangerousFinding checks if a finding type relates to dangerous accounts
func isDangerousFinding(findingType string) bool {
	dangerousTypes := map[string]bool{
		"ACCOUNT_OPERATORS_MEMBER":     true,
		"BACKUP_OPERATORS_MEMBER":      true,
		"SERVER_OPERATORS_MEMBER":      true,
		"PRINT_OPERATORS_MEMBER":       true,
		"DNS_ADMINS_MEMBER":            true,
		"DANGEROUS_BUILTIN_MEMBERSHIP": true,
		"BUILTIN_MODIFIED":             true,
	}
	return dangerousTypes[findingType]
}

// isServiceFinding checks if a finding type relates to service accounts
func isServiceFinding(findingType string) bool {
	serviceTypes := map[string]bool{
		"SERVICE_ACCOUNT_INTERACTIVE":  true,
		"SERVICE_ACCOUNT_NAMING":       true,
		"SERVICE_ACCOUNT_NO_PREAUTH":   true,
		"SERVICE_ACCOUNT_OLD_PASSWORD": true,
		"SERVICE_ACCOUNT_PRIVILEGED":   true,
		"SERVICE_ACCOUNT_WITH_SPN":     true,
		"KERBEROASTING_RISK":           true,
	}
	return serviceTypes[findingType]
}
