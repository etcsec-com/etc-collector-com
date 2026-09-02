package audit

import (
	"sort"
	"strings"

	"github.com/etcsec-com/etc-collector/pkg/types"
)

// GPOPolicy represents parsed Group Policy settings from SYSVOL
type GPOPolicy struct {
	GUID        string
	DisplayName string

	// Parsed from GptTmpl.inf
	KerberosPolicy  *KerberosPolicy
	SystemAccess    *SystemAccess
	EventAudit      *EventAudit
	PrivilegeRights *PrivilegeRights

	// v3.1.18 — parsed from GptTmpl.inf [Group Membership] section.
	// Each entry pins which SIDs are members of a privileged group on the
	// targeted endpoints. Used by ANSSI Guide M29 + BP-039 R13.
	RestrictedGroups []RestrictedGroupSpec

	// Parsed from Registry.pol
	RegistrySettings *RegistrySettings

	// T_132/D3 — parsed from MACHINE\Microsoft\Windows NT\Audit\audit.csv
	// (Advanced Audit Policy Configuration). Keyed by subcategory GUID,
	// lowercased with braces (e.g. "{0cce9215-69ae-11d9-bed3-505054503030}"
	// for the "Logon" subcategory), value is the raw Setting Value column
	// (0=No Auditing, 1=Success, 2=Failure, 3=Success and Failure — the
	// same scale as EventAudit's fields). Unlike EventAudit, this is not
	// something [Event Audit]'s absence can be assumed to represent: many
	// domains configure the effective audit policy outside of any GPO
	// entirely, which audit.csv's own absence cannot distinguish from
	// "nothing audited" (see internal/audit/detectors/ad/compliance/auditpolicy).
	AdvancedAudit map[string]int
}

// KerberosPolicy represents [Kerberos Policy] from GptTmpl.inf
type KerberosPolicy struct {
	MaxTicketAge         int // hours (default: 10)
	MaxRenewAge          int // days (default: 7)
	MaxServiceAge        int // minutes (default: 600)
	MaxClockSkew         int // minutes (default: 5)
	TicketValidateClient int // 0 or 1
}

// SystemAccess represents [System Access] from GptTmpl.inf
type SystemAccess struct {
	MinimumPasswordLength int
	PasswordHistorySize   int
	MaximumPasswordAge    int // days
	MinimumPasswordAge    int // days
	LockoutBadCount       int
	LockoutDuration       int // minutes
	ResetLockoutCount     int // minutes
	PasswordComplexity    int // 0 or 1
	ClearTextPassword     int // 0 or 1
}

// EventAudit represents [Event Audit] from GptTmpl.inf
type EventAudit struct {
	AuditAccountLogon    int // 0=None, 1=Success, 2=Failure, 3=Both
	AuditAccountManage   int
	AuditDSAccess        int
	AuditLogonEvents     int
	AuditObjectAccess    int
	AuditPolicyChange    int
	AuditPrivilegeUse    int
	AuditProcessTracking int
	AuditSystemEvents    int
}

// PrivilegeRights represents [Privilege Rights] from GptTmpl.inf
type PrivilegeRights struct {
	SeEnableDelegationPrivilege []string // SIDs with delegation privilege
	SeDebugPrivilege            []string // SIDs with debug privilege
	SeBackupPrivilege           []string // SIDs with backup privilege
	SeTcbPrivilege              []string // SIDs with "Act as part of the operating system"
	SeRestorePrivilege          []string // SIDs with restore privilege
	SeLoadDriverPrivilege       []string // SIDs with load driver privilege

	// v3.1.18 — deny rights used by ANSSI PA-099 R82+R83 (restrict access
	// from Tier 0 systems to less-trusted accounts).
	SeDenyNetworkLogonRight           []string // SIDs denied network logon
	SeDenyInteractiveLogonRight       []string // SIDs denied interactive logon
	SeDenyRemoteInteractiveLogonRight []string // SIDs denied RDP logon
	SeDenyServiceLogonRight           []string // SIDs denied service logon
	SeDenyBatchLogonRight             []string // SIDs denied batch logon
}

// RegistrySettings represents parsed Registry.pol settings
type RegistrySettings struct {
	// SMB signing
	RequireSMBSigningServer *int // LanmanServer\Parameters\RequireSecuritySignature
	RequireSMBSigningClient *int // LanmanWorkstation\Parameters\RequireSecuritySignature

	// LDAP
	LDAPServerIntegrity *int // NTDS\Parameters\LDAPServerIntegrity (0=none, 1=negotiate, 2=require)
	LDAPChannelBinding  *int // NTDS\Parameters\LdapEnforceChannelBinding (0=never, 1=when-supported, 2=always)

	// SMBv1
	SMB1Enabled *int // LanmanServer\Parameters\SMB1 (0=disabled, 1=enabled)

	// PowerShell logging
	PSScriptBlockLogging   *int // 0=disabled, 1=enabled
	PSModuleLogging        *int // 0=disabled, 1=enabled
	PSTranscriptionEnabled *int // 0=disabled, 1=enabled (EnableTranscripting)

	// Event log
	SecurityLogMaxSizeKB *int // MaxSize for Security event log

	// Phase 2: Network security
	LLMNRDisabled          *int // DNSClient\EnableMulticast (0=LLMNR disabled, 1=enabled)
	KerberosArmoringDC     *int // KDC\SupportedEncryptionTypes or KDC\SupportedEtypes for FAST
	KerberosArmoringClient *int // Kerberos\Parameters\RequireFast (1=require FAST/armoring)

	// Phase 2: Terminal Services / RDP
	RDPDenyConnections *int // Terminal Services\fDenyTSConnections (1=deny)
	RDPSecurityLayer   *int // Terminal Services\SecurityLayer (0=RDP, 1=negotiate, 2=TLS)
	RDPNLA             *int // Terminal Services\UserAuthentication (1=NLA required)

	// Phase 2: Hardened UNC Paths
	HardenedPathsNetlogon *string // NetworkProvider\HardenedPaths \\*\NETLOGON
	HardenedPathsSysvol   *string // NetworkProvider\HardenedPaths \\*\SYSVOL

	// Phase 2: NetCease / session hardening
	NetSessionHardening *int // LanmanServer\DefaultSecurity\SrvsvcSessionInfo

	// Phase 2: Defender ASR
	DefenderASREnabled *int // Windows Defender Exploit Guard\ASR

	// Phase 2: Firewall
	FirewallOutboundAction *int // WindowsFirewall\DomainProfile\DefaultOutboundAction

	// Phase 4: Credential security
	WDigestUseLogonCredential *int    // WDigest\UseLogonCredential (0=disabled)
	LSARunAsPPL               *int    // Lsa\RunAsPPL (1=enabled)
	CredentialGuardEnabled    *int    // DeviceGuard\EnableVirtualizationBasedSecurity
	LmCompatibilityLevel      *int    // Lsa\LmCompatibilityLevel (5=NTLMv2 only)
	CachedLogonsCount         *int    // Winlogon\CachedLogonsCount
	RestrictRemoteSAM         *string // SAM\RestrictRemoteSam

	// Phase 4: Infrastructure
	WUServer                 *string // WindowsUpdate\WUServer (http:// = insecure)
	PointAndPrintNoElevation *int    // Windows NT\Printers\PointAndPrint\NoWarningNoElevationOnInstall
	ZerologonEnforcement     *int    // Netlogon\Parameters\FullSecureChannelProtection
	BitLockerRequired        *int    // FVE\RequireDeviceEncryption

	// v3.1.17 — VBS / HVCI / Credential Guard scope (ANSSI BP-039 R5/R8/R9/R10/R14)
	//
	// Note: the legacy field CredentialGuardEnabled above maps to
	// DeviceGuard\EnableVirtualizationBasedSecurity which is actually the VBS
	// master switch (not Credential Guard itself). The dedicated Credential
	// Guard control is LsaCfgFlags. We keep both for clarity:
	//   - VBS itself: CredentialGuardEnabled (mis-named, kept for BC)
	//   - HVCI: HVCIEnabled (DeviceGuard\HypervisorEnforcedCodeIntegrity)
	//   - Credential Guard: LsaCfgFlags (0=off, 1=enabled, 2=enabled w/ UEFI lock)
	//   - Code Integrity policy enforcement: DeviceGuardCodeIntegrityPolicyEnforcement
	HVCIEnabled                               *int    // DeviceGuard\HypervisorEnforcedCodeIntegrity (1, 2)
	LsaCfgFlags                               *int    // Lsa\LsaCfgFlags (Credential Guard 0/1/2)
	DeviceGuardCodeIntegrityPolicyEnforcement *int    // DeviceGuard\RequirePlatformSecurityFeatures
	DeviceGuardConfigCIPolicyFilePath         *string // CodeIntegrity\ConfigCIPolicyFilePath (CCI/WDAC marker)

	// v3.1.17 — NTLM outbound blocking (ANSSI PA-099 R73 / R74+)
	// 0 = allow all, 1 = audit, 2 = deny all
	RestrictSendingNTLMTraffic   *int // Lsa\MSV1_0\RestrictSendingNTLMTraffic
	RestrictReceivingNTLMTraffic *int // Lsa\MSV1_0\RestrictReceivingNTLMTraffic

	// v3.1.18 — RDP encryption hardening (ANSSI PA-099 R79)
	RDPMinEncryptionLevel *int // Terminal Services\MinEncryptionLevel (3 = high)
	RDPEncryptRPCTraffic  *int // Terminal Services\fEncryptRPCTraffic (1 = required)

	// Folder Options / File associations (S-FolderOptions)
	FolderOptionsDefaultFileTypeRisk *int    // Policies\Associations\DefaultFileTypeRisk
	FolderOptionsLowRiskFileTypes    *string // Policies\Associations\LowRiskFileTypes
}

// RestrictedGroupSpec represents one entry from the GptTmpl.inf
// [Group Membership] section. Format on disk:
//
//	[Group Membership]
//	*S-1-5-32-544__Members = *S-1-5-21-...-512,*S-1-5-21-...-XXXX
//	*S-1-5-32-544__Memberof =
//
// `__Members` enumerates the SIDs that ARE members of the group (replaces
// existing members on apply). `__Memberof` enumerates groups the principal
// is added to. ANSSI Guide M29 + BP-039 R13 use this to constrain local
// Administrators on workstations.
//
// v3.1.18 — replaces the previous M29 heuristic that matched on GPO name.
type RestrictedGroupSpec struct {
	GroupSID     string   // e.g. "S-1-5-32-544" (BUILTIN\Administrators)
	GroupName    string   // resolved if known; empty otherwise
	MembersSIDs  []string // SIDs explicitly allowed in the group
	MemberOfSIDs []string // SIDs the group is added to
}

// (RestrictedGroups field added to GPOPolicy struct above.)

// SYSVOLFinding represents a security finding from SYSVOL scanning
type SYSVOLFinding struct {
	Type     string // "cpassword", "orphaned_ldap", "orphaned_sysvol"
	GPOGUID  string
	GPOName  string
	FilePath string
	Details  string
}

// intPtr returns a pointer to an int value
func intPtr(v int) *int {
	return &v
}

// ---------------------------------------------------------------------------
// T_003 — asset-entities P2 §6: eager GPO/OU inventory shaping helpers.
//
// These build the fully-typed AffectedEntity for the INFO_DOMAIN_GPO_INVENTORY
// and INFO_DOMAIN_OU_INVENTORY detectors from data already collected by the
// LDAP provider (GetGPOs/GetOUs/GetGPOLinks/GetGPOAcls) — no new collection.
// Every slice is initialised non-nil so the emitted JSON is [] never null.
// ---------------------------------------------------------------------------

// normGUID lowercases a GPO identifier and strips the {} braces so the
// {GUID}-with-braces CN form and the bare-GUID gPLink form match.
func normGUID(s string) string {
	return strings.ToLower(strings.Trim(strings.TrimSpace(s), "{}"))
}

// linkScope classifies a GPO-link target DN as Domain, OU or Site.
func linkScope(dn string) string {
	u := strings.ToUpper(strings.TrimSpace(dn))
	switch {
	case strings.HasPrefix(u, "OU="):
		return "OU"
	case strings.Contains(u, "CN=SITES,"):
		return "Site"
	case strings.HasPrefix(u, "DC="):
		return "Domain"
	default:
		return ""
	}
}

// gpoIndex maps every collected GPO by its normalised GUID (both the CN and the
// GUID field, which the provider currently sets to the same {GUID} value).
func gpoIndex(data *DetectorData) map[string]types.GPO {
	idx := make(map[string]types.GPO, len(data.GPOs))
	for _, g := range data.GPOs {
		if k := normGUID(g.CN); k != "" {
			idx[k] = g
		}
		if k := normGUID(g.GUID); k != "" {
			idx[k] = g
		}
	}
	return idx
}

// GPOEntity builds the eager inventory AffectedEntity for a single GPO.
func GPOEntity(g types.GPO, data *DetectorData) types.AffectedEntity {
	key := normGUID(g.CN)
	if key == "" {
		key = normGUID(g.GUID)
	}

	linkedTo := make([]types.EntityGPOLink, 0)
	for _, l := range data.GPOLinks {
		if normGUID(l.GPOCN) == key || (l.GPOGuid != "" && normGUID(l.GPOGuid) == key) {
			linkedTo = append(linkedTo, types.EntityGPOLink{
				DN:       l.LinkedTo,
				Scope:    linkScope(l.LinkedTo),
				Enforced: l.Enforced,
				Enabled:  l.LinkEnabled,
			})
		}
	}

	name := g.DisplayName
	if name == "" {
		name = g.Name
	}

	return types.AffectedEntity{
		Type:        types.EntityTypeGPO,
		DN:          g.DN,
		Name:        name,
		DisplayName: g.DisplayName,
		Enabled:     g.Enabled,
		LinkedTo:    linkedTo,
		Delegations: gpoPermissions(g.DN, data), // rendered as permissions[]
		WmiFilter:   "",                         // gPCWQLFilter not collected → null (follow-up)
	}
}

// gpoPermissions groups a GPO's ACL entries by trustee SID into one delegation
// record per trustee, each carrying the aggregated set of right names.
func gpoPermissions(gpoDN string, data *DetectorData) []types.EntityDelegation {
	rightsBySID := map[string]map[string]bool{}
	order := make([]string, 0)
	for _, a := range data.GPOAcls {
		if !strings.EqualFold(a.GPODN, gpoDN) {
			continue
		}
		sid := a.TrusteeSID
		if sid == "" {
			sid = a.Trustee
		}
		if sid == "" {
			continue
		}
		right := AccessMaskToRight(a.AccessMask, "")
		if right == "" {
			right = "Read"
		}
		if _, ok := rightsBySID[sid]; !ok {
			rightsBySID[sid] = map[string]bool{}
			order = append(order, sid)
		}
		rightsBySID[sid][right] = true
	}

	out := make([]types.EntityDelegation, 0, len(order))
	for _, sid := range order {
		rights := make([]string, 0, len(rightsBySID[sid]))
		for r := range rightsBySID[sid] {
			rights = append(rights, r)
		}
		sort.Strings(rights)
		out = append(out, types.EntityDelegation{
			Trustee: sid,
			Name:    resolvedName(sid, data),
			Rights:  rights,
		})
	}
	return out
}

// resolvedName best-effort resolves a trustee SID to a principal name via the
// SID cache / well-known table. Returns "" when unresolved.
func resolvedName(sid string, data *DetectorData) string {
	ent := SIDToEntityWithCache(sid, data)
	if ent.Name != "" {
		return ent.Name
	}
	return ent.SAMAccountName
}

// OUEntity builds the eager inventory AffectedEntity for a single OU.
func OUEntity(ou types.OU, data *DetectorData) types.AffectedEntity {
	gpoIdx := gpoIndex(data)

	linkedGpos := make([]types.EntityOULink, 0)
	for _, l := range data.GPOLinks {
		if !strings.EqualFold(l.LinkedTo, ou.DN) {
			continue
		}
		g, ok := gpoIdx[normGUID(l.GPOCN)]
		if !ok && l.GPOGuid != "" {
			g, ok = gpoIdx[normGUID(l.GPOGuid)]
		}
		link := types.EntityOULink{
			DN:       l.GPOCN, // fall back to the link's CN when the GPO isn't in the typed set
			Enforced: l.Enforced,
			Enabled:  l.LinkEnabled,
			Order:    l.Order,
		}
		if ok {
			link.DN = g.DN
			link.Name = g.DisplayName
		}
		linkedGpos = append(linkedGpos, link)
	}

	cc := ouChildCounts(ou.DN, data)
	return types.AffectedEntity{
		Type:        types.EntityTypeOU,
		DN:          ou.DN,
		Name:        ou.Name,
		Description: types.RedactSecrets(ou.Description),
		LinkedGpos:  linkedGpos,
		ChildCounts: &cc,
		Delegations: make([]types.EntityDelegation, 0), // OU DACL delegations: follow-up (needs OU ACL wiring)
	}
}

// ouChildCounts censuses the DIRECT children of an OU by object class. A DN is a
// direct child when it ends with ",<ouDN>" and the leading RDN has no further
// comma (i.e. exactly one level below the OU).
func ouChildCounts(ouDN string, data *DetectorData) types.EntityChildCounts {
	cc := types.EntityChildCounts{}
	suffix := "," + ouDN
	upperSuffix := strings.ToUpper(suffix)
	isDirectChild := func(dn string) bool {
		if !strings.HasSuffix(strings.ToUpper(dn), upperSuffix) {
			return false
		}
		prefix := dn[:len(dn)-len(suffix)]
		return prefix != "" && !strings.Contains(prefix, ",")
	}
	for _, u := range data.Users {
		if isDirectChild(u.DN) {
			cc.Users++
		}
	}
	for _, c := range data.Computers {
		if isDirectChild(c.DN) {
			cc.Computers++
		}
	}
	for _, g := range data.Groups {
		if isDirectChild(g.DN) {
			cc.Groups++
		}
	}
	for _, o := range data.OUs {
		if isDirectChild(o.DN) {
			cc.OUs++
		}
	}
	return cc
}
