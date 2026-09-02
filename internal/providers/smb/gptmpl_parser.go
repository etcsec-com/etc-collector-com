// Package smb provides SMB/CIFS client functionality for Group Policy Object (GPO) parsing.
//
// This file implements parsing of GptTmpl.inf files, which are INI-format configuration files
// that define security policy templates deployed via GPO.
//
// # GptTmpl.inf Overview
//
// GptTmpl.inf files are stored in SYSVOL at:
//
//	\\domain.com\SYSVOL\domain.com\Policies\{GPO-GUID}\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf
//
// These files define domain-wide security policies including:
//   - Kerberos ticket lifetimes and validation settings
//   - Password complexity, length, age, lockout policies
//   - Audit logging configuration (which events to log)
//   - Privileged user rights assignments (who can enable delegation, debug programs, etc.)
//   - Registry security settings (referenced from Security Templates)
//
// # Why This Matters for Security
//
// Weak GptTmpl.inf settings create domain-wide vulnerabilities:
//   - No password complexity → easily guessed/cracked passwords
//   - Long password age → stale credentials persist
//   - No account lockout → unlimited brute force attempts
//   - Missing audit configuration → attacks go undetected
//   - Overly permissive privilege assignments → too many users can perform dangerous operations
//   - Long Kerberos ticket lifetimes → stolen tickets valid for extended periods
//
// # INI File Format
//
// GptTmpl.inf uses standard Windows INI format with UTF-16LE or UTF-8 encoding:
//
//	[SectionName]
//	Key1=Value1
//	Key2=Value2
//
//	[AnotherSection]
//	Key3=Value3
//	; Comments start with semicolon
//
// # File Encoding
//
// GptTmpl.inf files may use different encodings:
//   - UTF-16LE with BOM (0xFF 0xFE) - Common on modern Windows
//   - UTF-16BE with BOM (0xFE 0xFF) - Rare
//   - UTF-8 with BOM (0xEF 0xBB 0xBF) - Sometimes used
//   - ASCII/UTF-8 without BOM - Legacy systems
//
// The parser detects BOM and decodes accordingly.
//
// # Sections and Settings
//
// ## [Kerberos Policy]
//
// Controls Kerberos ticket lifetimes and validation:
//
//	Setting               | Units   | Default | Recommended | Security Impact
//	----------------------|---------|---------|-------------|----------------------------------
//	MaxTicketAge          | hours   | 10      | 10          | TGT lifetime (shorter = more secure)
//	MaxRenewAge           | days    | 7       | 7           | Max TGT renewal period
//	MaxServiceAge         | minutes | 600     | 600         | TGS ticket lifetime
//	MaxClockSkew          | minutes | 5       | 5           | Allowed time drift (Kerberos)
//	TicketValidateClient  | boolean | 1       | 1           | Validate PAC (prevents forgery)
//
// Long ticket lifetimes → stolen tickets valid longer → higher risk.
//
// ## [System Access]
//
// Password and account lockout policies:
//
//	Setting                 | Units    | Default | Recommended | Security Impact
//	------------------------|----------|---------|-------------|----------------------------------
//	MinimumPasswordLength   | chars    | 7       | 14+         | Longer = harder to brute force
//	PasswordHistorySize     | passwords| 24      | 24          | Prevents password reuse
//	MaximumPasswordAge      | days     | 42      | 60-90       | Forces periodic changes
//	MinimumPasswordAge      | days     | 1       | 1           | Prevents rapid password cycling
//	LockoutBadCount         | attempts | 0       | 5           | Account lockout threshold (0=unlimited)
//	ResetLockoutCount       | minutes  | 30      | 30          | Reset failed attempt counter after
//	LockoutDuration         | minutes  | 30      | 30          | Account locked for this duration
//	PasswordComplexity      | boolean  | 0       | 1           | Require uppercase, lowercase, digit, symbol
//	ClearTextPassword       | boolean  | 0       | 0           | Allow reversible encryption (INSECURE!)
//
// Weak password policies → easily compromised accounts → domain breach.
//
// ## [Event Audit]
//
// Audit logging configuration (bitmask values):
//
//	0 = No auditing
//	1 = Success only
//	2 = Failure only
//	3 = Success and Failure (recommended for security-critical events)
//
//	Setting                  | Audit Type                      | Recommended
//	-------------------------|---------------------------------|-------------
//	AuditAccountLogon        | Domain authentication events    | 3 (both)
//	AuditAccountManage       | Account/group creation/deletion | 3 (both)
//	AuditDSAccess            | AD object access                | 2 (failures)
//	AuditLogonEvents         | Interactive/network logon       | 3 (both)
//	AuditObjectAccess        | File/registry access            | 0 (noisy)
//	AuditPolicyChange        | Audit policy changes            | 3 (both)
//	AuditPrivilegeUse        | Sensitive privilege use         | 2 (failures)
//	AuditProcessTracking     | Process creation/termination    | 0 (noisy)
//	AuditSystemEvents        | System startup/shutdown         | 3 (both)
//
// Missing audit configuration → attacks undetected → delayed incident response.
//
// ## [Privilege Rights]
//
// Assigns Windows privileges to users/groups (SID list format):
//
//	Setting                        | Privilege                           | Security Risk if Over-Granted
//	-------------------------------|-------------------------------------|--------------------------------
//	SeEnableDelegationPrivilege    | Enable computer/user delegation     | Allows Kerberos delegation abuse
//	SeTcbPrivilege                 | Act as part of OS                   | Full system compromise
//	SeDebugPrivilege               | Debug programs                      | Memory dump, process injection
//	SeBackupPrivilege              | Back up files/directories           | Read any file, bypass ACLs
//	SeRestorePrivilege             | Restore files/directories           | Write any file, bypass ACLs
//	SeLoadDriverPrivilege          | Load kernel drivers                 | Kernel-mode rootkits
//
// Value format: *S-1-5-32-544,*S-1-5-21-...-512
//   - Comma-separated SID list
//   - Asterisk (*) prefix indicates SID
//   - Example: *S-1-5-32-544 = Local Administrators group
//
// Over-assigned privileges → privilege escalation → domain compromise.
//
// ## [Registry Values]
//
// References registry settings for security controls (format: path=type,value):
//
//	Format: MACHINE\System\Path\To\Key\ValueName=type,value
//	Example: MACHINE\System\CurrentControlSet\Services\LanmanServer\Parameters\RequireSecuritySignature=4,1
//
// Type codes (REG_* constants):
//
//	1 = REG_SZ (string)
//	4 = REG_DWORD (32-bit integer)
//	7 = REG_MULTI_SZ (multi-line string)
//
// See registrypol_parser.go documentation for security-relevant registry keys.
//
// # Parsing Algorithm
//
//  1. Detect and strip BOM (UTF-16LE/BE/UTF-8)
//  2. Decode to UTF-8 string
//  3. Parse INI structure:
//     a. Lines starting with '[' = section headers
//     b. Lines with '=' = key-value pairs
//     c. Lines starting with ';' = comments (ignored)
//     d. Empty lines ignored
//  4. Extract security settings from known sections
//  5. Return structured data for detector consumption
//
// # Value Interpretation Examples
//
// Password Policy:
//
//	MinimumPasswordLength=14 → passwords must be at least 14 characters
//	PasswordComplexity=1 → must contain uppercase, lowercase, digit, symbol
//	LockoutBadCount=5 → account locks after 5 failed login attempts
//
// Kerberos Policy:
//
//	MaxTicketAge=10 → TGT valid for 10 hours (600 minutes)
//	TicketValidateClient=1 → validate PAC signature (prevents golden ticket with old keys)
//
// Audit Policy:
//
//	AuditAccountLogon=3 → log both successful (1) and failed (2) domain authentications
//	AuditAccountManage=3 → log both successful and failed account/group changes
//
// Registry Values:
//
//	MACHINE\...\LanmanServer\Parameters\RequireSecuritySignature=4,1
//	→ Type 4 (DWORD), value 1 (enabled) → SMB signing required on server
//
// # Security Analysis Use Cases
//
// Detectors use parsed GptTmpl.inf data to identify:
//   - Weak password policies (length < 14, complexity disabled, no lockout)
//   - Missing audit configuration (critical events not logged)
//   - Dangerous privilege assignments (too many users with SeEnableDelegationPrivilege)
//   - Insecure Kerberos settings (long ticket lifetimes, no PAC validation)
//   - Cleartext password storage enabled (PasswordReversibleEncryption=1)
//
// # References
//
// - MS-GPPREF: Group Policy: Policy File Format
// - Security Templates documentation (Microsoft TechNet)
// - CIS Benchmarks: Windows Server security configuration baselines
// - NIST SP 800-53: Security and Privacy Controls (password/audit policies)
package smb

import (
	"strconv"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
)

// ParseGptTmpl parses a GptTmpl.inf file content (INI-like format)
// Returns parsed sections: Kerberos Policy, System Access, Event Audit, Privilege Rights, Registry Settings
// ParseGptTmpl parses a GptTmpl.inf file content (INI-like format).
//
// Returns the security policy structs collected from each known section.
// v3.1.18 added the [Group Membership] return (Restricted Groups) used by
// ANSSI Guide M29 / BP-039 R13. Returns nil for any section absent from the
// file.
func ParseGptTmpl(data []byte) (*audit.KerberosPolicy, *audit.SystemAccess, *audit.EventAudit, *audit.PrivilegeRights, *audit.RegistrySettings, []audit.RestrictedGroupSpec) {
	sections := parseINI(data)

	var kp *audit.KerberosPolicy
	var sa *audit.SystemAccess
	var ea *audit.EventAudit
	var pr *audit.PrivilegeRights
	var rs *audit.RegistrySettings
	var rg []audit.RestrictedGroupSpec

	// [Kerberos Policy]
	if sec, ok := sections["Kerberos Policy"]; ok {
		kp = &audit.KerberosPolicy{}
		if v, ok := sec["MaxTicketAge"]; ok {
			kp.MaxTicketAge = atoi(v)
		}
		if v, ok := sec["MaxRenewAge"]; ok {
			kp.MaxRenewAge = atoi(v)
		}
		if v, ok := sec["MaxServiceAge"]; ok {
			kp.MaxServiceAge = atoi(v)
		}
		if v, ok := sec["MaxClockSkew"]; ok {
			kp.MaxClockSkew = atoi(v)
		}
		if v, ok := sec["TicketValidateClient"]; ok {
			kp.TicketValidateClient = atoi(v)
		}
	}

	// [System Access]
	if sec, ok := sections["System Access"]; ok {
		sa = &audit.SystemAccess{}
		if v, ok := sec["MinimumPasswordLength"]; ok {
			sa.MinimumPasswordLength = atoi(v)
		}
		if v, ok := sec["PasswordHistorySize"]; ok {
			sa.PasswordHistorySize = atoi(v)
		}
		if v, ok := sec["MaximumPasswordAge"]; ok {
			sa.MaximumPasswordAge = atoi(v)
		}
		if v, ok := sec["MinimumPasswordAge"]; ok {
			sa.MinimumPasswordAge = atoi(v)
		}
		if v, ok := sec["LockoutBadCount"]; ok {
			sa.LockoutBadCount = atoi(v)
		}
		if v, ok := sec["ResetLockoutCount"]; ok {
			sa.ResetLockoutCount = atoi(v)
		}
		if v, ok := sec["LockoutDuration"]; ok {
			sa.LockoutDuration = atoi(v)
		}
		if v, ok := sec["PasswordComplexity"]; ok {
			sa.PasswordComplexity = atoi(v)
		}
		if v, ok := sec["ClearTextPassword"]; ok {
			sa.ClearTextPassword = atoi(v)
		}
	}

	// [Event Audit]
	if sec, ok := sections["Event Audit"]; ok {
		ea = &audit.EventAudit{}
		if v, ok := sec["AuditAccountLogon"]; ok {
			ea.AuditAccountLogon = atoi(v)
		}
		if v, ok := sec["AuditAccountManage"]; ok {
			ea.AuditAccountManage = atoi(v)
		}
		if v, ok := sec["AuditDSAccess"]; ok {
			ea.AuditDSAccess = atoi(v)
		}
		if v, ok := sec["AuditLogonEvents"]; ok {
			ea.AuditLogonEvents = atoi(v)
		}
		if v, ok := sec["AuditObjectAccess"]; ok {
			ea.AuditObjectAccess = atoi(v)
		}
		if v, ok := sec["AuditPolicyChange"]; ok {
			ea.AuditPolicyChange = atoi(v)
		}
		if v, ok := sec["AuditPrivilegeUse"]; ok {
			ea.AuditPrivilegeUse = atoi(v)
		}
		if v, ok := sec["AuditProcessTracking"]; ok {
			ea.AuditProcessTracking = atoi(v)
		}
		if v, ok := sec["AuditSystemEvents"]; ok {
			ea.AuditSystemEvents = atoi(v)
		}
	}

	// [Privilege Rights]
	if sec, ok := sections["Privilege Rights"]; ok {
		pr = &audit.PrivilegeRights{}
		if v, ok := sec["SeEnableDelegationPrivilege"]; ok {
			pr.SeEnableDelegationPrivilege = parseSIDList(v)
		}
		if v, ok := sec["SeDebugPrivilege"]; ok {
			pr.SeDebugPrivilege = parseSIDList(v)
		}
		if v, ok := sec["SeBackupPrivilege"]; ok {
			pr.SeBackupPrivilege = parseSIDList(v)
		}
		if v, ok := sec["SeTcbPrivilege"]; ok {
			pr.SeTcbPrivilege = parseSIDList(v)
		}
		if v, ok := sec["SeRestorePrivilege"]; ok {
			pr.SeRestorePrivilege = parseSIDList(v)
		}
		if v, ok := sec["SeLoadDriverPrivilege"]; ok {
			pr.SeLoadDriverPrivilege = parseSIDList(v)
		}
		// v3.1.18 — deny rights for ANSSI R82/R83
		if v, ok := sec["SeDenyNetworkLogonRight"]; ok {
			pr.SeDenyNetworkLogonRight = parseSIDList(v)
		}
		if v, ok := sec["SeDenyInteractiveLogonRight"]; ok {
			pr.SeDenyInteractiveLogonRight = parseSIDList(v)
		}
		if v, ok := sec["SeDenyRemoteInteractiveLogonRight"]; ok {
			pr.SeDenyRemoteInteractiveLogonRight = parseSIDList(v)
		}
		if v, ok := sec["SeDenyServiceLogonRight"]; ok {
			pr.SeDenyServiceLogonRight = parseSIDList(v)
		}
		if v, ok := sec["SeDenyBatchLogonRight"]; ok {
			pr.SeDenyBatchLogonRight = parseSIDList(v)
		}
	}

	// [Registry Values] - format: MACHINE\path\to\key=type,value
	// type 4 = REG_DWORD, type 1 = REG_SZ, type 7 = REG_MULTI_SZ
	if sec, ok := sections["Registry Values"]; ok {
		rs = parseRegistryValues(sec)
	}

	// v3.1.18 — [Group Membership] = Restricted Groups (ANSSI M29 / BP-039 R13)
	if sec, ok := sections["Group Membership"]; ok {
		rg = parseGroupMembership(sec)
	}

	return kp, sa, ea, pr, rs, rg
}

// parseGroupMembership parses the [Group Membership] section of GptTmpl.inf.
// Lines come in two flavors:
//
//	*S-1-5-32-544__Members  = *S-1-5-21-...-512,*S-1-5-21-...-XXXX
//	*S-1-5-32-544__Memberof = *S-1-5-21-...-XXXX
//
// The leading `*` denotes a SID (vs a name). The token before `__` is the
// principal whose membership is being defined.
//
// We aggregate per-principal: one RestrictedGroupSpec per distinct SID.
func parseGroupMembership(sec map[string]string) []audit.RestrictedGroupSpec {
	if len(sec) == 0 {
		return nil
	}
	by := map[string]*audit.RestrictedGroupSpec{}

	for key, val := range sec {
		key = strings.TrimSpace(key)
		val = strings.TrimSpace(val)
		// Split "PRINCIPAL__Members" or "PRINCIPAL__Memberof"
		idx := strings.Index(key, "__")
		if idx < 0 {
			continue
		}
		principal := strings.TrimPrefix(key[:idx], "*")
		suffix := key[idx+2:]

		spec, ok := by[principal]
		if !ok {
			spec = &audit.RestrictedGroupSpec{
				GroupSID:  principal,
				GroupName: wellKnownSIDName(principal),
			}
			by[principal] = spec
		}

		members := parseSIDList(val) // re-use the same helper as Privilege Rights
		switch strings.ToLower(suffix) {
		case "members":
			spec.MembersSIDs = members
		case "memberof":
			spec.MemberOfSIDs = members
		}
	}

	out := make([]audit.RestrictedGroupSpec, 0, len(by))
	for _, s := range by {
		out = append(out, *s)
	}
	return out
}

// wellKnownSIDName returns a friendly name for a few well-known SIDs that
// commonly appear in [Group Membership]. Returns empty string if unknown.
// Tier 0-relevant entries primarily (BUILTIN local groups).
func wellKnownSIDName(sid string) string {
	switch sid {
	case "S-1-5-32-544":
		return "BUILTIN\\Administrators"
	case "S-1-5-32-545":
		return "BUILTIN\\Users"
	case "S-1-5-32-548":
		return "BUILTIN\\Account Operators"
	case "S-1-5-32-549":
		return "BUILTIN\\Server Operators"
	case "S-1-5-32-550":
		return "BUILTIN\\Print Operators"
	case "S-1-5-32-551":
		return "BUILTIN\\Backup Operators"
	case "S-1-5-32-555":
		return "BUILTIN\\Remote Desktop Users"
	case "S-1-5-32-580":
		return "BUILTIN\\Remote Management Users"
	}
	return ""
}

// parseRegistryValues extracts security-relevant registry settings from [Registry Values] section.
//
// Entry Format: MACHINE\System\Path\To\Key\ValueName=type,value
//
// Example:
//
//	MACHINE\System\CurrentControlSet\Services\LanmanServer\Parameters\RequireSecuritySignature=4,1
//
// Parsing:
//   - Key: MACHINE\...\RequireSecuritySignature (registry path)
//   - Value: "4,1"
//   - Type: 4 (REG_DWORD)
//   - Data: 1 (enabled)
//
// Processes REG_DWORD (type 4) entries, plus REG_SZ/REG_EXPAND_SZ (type 1/2)
// entries for the handful of security-relevant settings that Windows only
// ever exposes as strings (e.g. RestrictRemoteSAM's SDDL, configured as a
// "Security Option" — administrators never set it via an Administrative
// Template/Registry.pol).
// Returns nil if no security-relevant settings found.
func parseRegistryValues(sec map[string]string) *audit.RegistrySettings {
	rs := &audit.RegistrySettings{}
	found := false

	for key, val := range sec {
		lower := strings.ToLower(key)
		parts := strings.SplitN(val, ",", 2)
		if len(parts) != 2 {
			continue
		}
		regType := strings.TrimSpace(parts[0])
		raw := strings.TrimSpace(parts[1])

		switch regType {
		case "4": // REG_DWORD
			dword := atoi(raw)
			switch {
			case strings.Contains(lower, "lanmanserver") && strings.Contains(lower, "requiresecuritysignature"):
				rs.RequireSMBSigningServer = &dword
				found = true
			case strings.Contains(lower, "lanmanworkstation") && strings.Contains(lower, "requiresecuritysignature"):
				rs.RequireSMBSigningClient = &dword
				found = true
			case strings.Contains(lower, "ntds") && strings.Contains(lower, "ldapserverintegrity"):
				rs.LDAPServerIntegrity = &dword
				found = true
			case strings.Contains(lower, "ntds") && strings.Contains(lower, "ldapenforcechannelbinding"):
				rs.LDAPChannelBinding = &dword
				found = true
			case strings.Contains(lower, "lanmanserver") && strings.Contains(lower, "smb1"):
				rs.SMB1Enabled = &dword
				found = true
			case strings.Contains(lower, "scriptblocklogging") && strings.Contains(lower, "enablescriptblocklogging"):
				rs.PSScriptBlockLogging = &dword
				found = true
			case strings.Contains(lower, "modulelogging") && strings.Contains(lower, "enablemodulelogging"):
				rs.PSModuleLogging = &dword
				found = true
			case strings.Contains(lower, "eventlog") && strings.Contains(lower, "security") && strings.Contains(lower, "maxsize"):
				rs.SecurityLogMaxSizeKB = &dword
				found = true
			case strings.Contains(lower, "dnsclient") && strings.Contains(lower, "enablemulticast"):
				rs.LLMNRDisabled = &dword
				found = true
			case strings.Contains(lower, "wdigest") && strings.Contains(lower, "uselogoncredential"):
				rs.WDigestUseLogonCredential = &dword
				found = true
			case strings.Contains(lower, "lsa") && !strings.Contains(lower, "lsass") && strings.Contains(lower, "runasppl"):
				rs.LSARunAsPPL = &dword
				found = true
			case strings.Contains(lower, "deviceguard") && strings.Contains(lower, "enablevirtualizationbasedsecurity"):
				rs.CredentialGuardEnabled = &dword
				found = true
			case strings.Contains(lower, "lsa") && !strings.Contains(lower, "lsass") && strings.Contains(lower, "lmcompatibilitylevel"):
				rs.LmCompatibilityLevel = &dword
				found = true
			case strings.Contains(lower, "netlogon") && strings.Contains(lower, "fullsecurechannelprotection"):
				rs.ZerologonEnforcement = &dword
				found = true
			case strings.Contains(lower, "pointandprint") && strings.Contains(lower, "nowarningnoelevationoninstall"):
				rs.PointAndPrintNoElevation = &dword
				found = true
			}
		case "1", "2": // REG_SZ / REG_EXPAND_SZ
			str := strings.Trim(raw, `"`)
			switch {
			// T_132/D2: RestrictRemoteSAM as a Security Option is REG_SZ
			// (an SDDL string), unlike every other registry-backed setting
			// in this function — it was previously invisible here twice
			// over: filtered by the REG_DWORD-only gate above, and with no
			// case for it even if that gate were passed.
			case strings.Contains(lower, "lsa") && !strings.Contains(lower, "lsass") && strings.Contains(lower, "restrictremotesam"):
				rs.RestrictRemoteSAM = &str
				found = true
			}
		}
	}

	if !found {
		return nil
	}
	return rs
}

// parseINI parses an INI-format file into a section→key→value map structure.
//
// INI Format:
//
//	[SectionName]
//	Key1=Value1
//	Key2=Value2
//	; Comment lines start with semicolon
//
// Handles UTF-16LE/BE BOMs by calling decodeText() first.
//
// Returns:
//
//	map[sectionName]map[key]value
//
// Example:
//
//	Input:
//	  [System Access]
//	  MinimumPasswordLength=14
//	  PasswordComplexity=1
//
//	Output:
//	  map["System Access"]["MinimumPasswordLength"] = "14"
//	  map["System Access"]["PasswordComplexity"] = "1"
func parseINI(data []byte) map[string]map[string]string {
	// Strip UTF-16LE BOM if present and convert to UTF-8
	text := decodeText(data)

	sections := make(map[string]map[string]string)
	currentSection := ""

	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, ";") {
			continue
		}

		// Section header
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			currentSection = line[1 : len(line)-1]
			if _, exists := sections[currentSection]; !exists {
				sections[currentSection] = make(map[string]string)
			}
			continue
		}

		// Key = Value
		if currentSection != "" {
			if idx := strings.Index(line, "="); idx != -1 {
				key := strings.TrimSpace(line[:idx])
				value := strings.TrimSpace(line[idx+1:])
				sections[currentSection][key] = value
			}
		}
	}

	return sections
}

// decodeText detects file encoding by BOM (Byte Order Mark) and converts to UTF-8.
//
// Supported BOMs:
//
//	0xFF 0xFE        → UTF-16LE (little-endian)
//	0xFE 0xFF        → UTF-16BE (big-endian)
//	0xEF 0xBB 0xBF   → UTF-8
//	No BOM           → Assume UTF-8/ASCII
//
// Windows systems often write GptTmpl.inf with UTF-16LE BOM, especially when
// modified via Group Policy Editor GUI.
func decodeText(data []byte) string {
	// Check for UTF-16LE BOM (0xFF 0xFE)
	if len(data) >= 2 && data[0] == 0xFF && data[1] == 0xFE {
		return decodeUTF16LE(data[2:])
	}
	// Check for UTF-16BE BOM (0xFE 0xFF)
	if len(data) >= 2 && data[0] == 0xFE && data[1] == 0xFF {
		return decodeUTF16BE(data[2:])
	}
	// Check for UTF-8 BOM
	if len(data) >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF {
		return string(data[3:])
	}
	return string(data)
}

// decodeUTF16LE decodes UTF-16LE (little-endian) encoded bytes to a Go string.
//
// UTF-16LE Encoding:
//   - 2 bytes per character (low byte first, high byte second)
//   - Example: 'A' (U+0041) → [0x41, 0x00]
//   - Example: '€' (U+20AC) → [0xAC, 0x20]
//
// Skips null characters (0x0000) as they are string terminators in UTF-16.
func decodeUTF16LE(data []byte) string {
	if len(data)%2 != 0 {
		data = data[:len(data)-1]
	}
	var sb strings.Builder
	for i := 0; i+1 < len(data); i += 2 {
		ch := rune(data[i]) | rune(data[i+1])<<8
		if ch == 0 {
			continue
		}
		sb.WriteRune(ch)
	}
	return sb.String()
}

// decodeUTF16BE decodes UTF-16BE (big-endian) encoded bytes to a Go string.
//
// UTF-16BE Encoding:
//   - 2 bytes per character (high byte first, low byte second)
//   - Example: 'A' (U+0041) → [0x00, 0x41]
//   - Example: '€' (U+20AC) → [0x20, 0xAC]
//
// Rare in Windows environments but supported for completeness.
func decodeUTF16BE(data []byte) string {
	if len(data)%2 != 0 {
		data = data[:len(data)-1]
	}
	var sb strings.Builder
	for i := 0; i+1 < len(data); i += 2 {
		ch := rune(data[i])<<8 | rune(data[i+1])
		if ch == 0 {
			continue
		}
		sb.WriteRune(ch)
	}
	return sb.String()
}

// parseSIDList parses comma-separated SID values from [Privilege Rights] section.
//
// Format: *S-1-5-32-544,*S-1-5-21-domain-512
//
// SID Prefix:
//   - Asterisk (*) indicates a SID (vs. username)
//   - Stripped during parsing
//
// Example:
//
//	Input:  "*S-1-5-32-544,*S-1-5-21-123-456-789-512"
//	Output: ["S-1-5-32-544", "S-1-5-21-123-456-789-512"]
//
// SID Meanings:
//   - S-1-5-32-544: Local Administrators (BUILTIN\Administrators)
//   - S-1-5-21-...-512: Domain Admins
//   - S-1-5-21-...-519: Enterprise Admins
func parseSIDList(value string) []string {
	var sids []string
	for _, sid := range strings.Split(value, ",") {
		sid = strings.TrimSpace(sid)
		sid = strings.TrimPrefix(sid, "*") // Remove * prefix
		if sid != "" {
			sids = append(sids, sid)
		}
	}
	return sids
}

// atoi converts a string to integer with error handling for malformed input.
//
// Handles edge cases:
//   - Whitespace: "  14  " → 14
//   - Comma-separated (some GptTmpl.inf files): "4, 0" → 4 (takes first value)
//   - Invalid: "abc" → 0 (returns zero on parse error)
//
// Used for parsing INI integer values like password length, ticket age, etc.
func atoi(s string) int {
	// Handle comma-separated values (e.g., "4, 0" in some GptTmpl.inf files)
	s = strings.TrimSpace(s)
	if idx := strings.Index(s, ","); idx != -1 {
		s = s[:idx]
	}
	v, _ := strconv.Atoi(strings.TrimSpace(s))
	return v
}
