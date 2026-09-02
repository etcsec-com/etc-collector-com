// Package smb provides SMB/CIFS client functionality for Group Policy Object (GPO) parsing.
//
// This file implements parsing of Registry.pol files, which are binary policy preference files
// deployed via GPO to configure Windows registry settings on domain-joined computers.
//
// # Registry.pol Overview
//
// Registry.pol files are stored in SYSVOL at:
//
//	\\domain.com\SYSVOL\domain.com\Policies\{GPO-GUID}\Machine\Registry.pol
//	\\domain.com\SYSVOL\domain.com\Policies\{GPO-GUID}\User\Registry.pol
//
// These files configure security settings such as:
//   - SMB signing requirements (SMBv1, SMBv2/3)
//   - LDAP signing and channel binding
//   - PowerShell logging (script block, module, transcription)
//   - Event log sizes and retention
//   - Security protocols (TLS versions, cipher suites)
//
// # Why This Matters for Security
//
// Weak GPO registry settings create domain-wide vulnerabilities:
//   - SMB signing disabled → NTLM relay attacks
//   - LDAP signing disabled → credential interception, MITM
//   - PowerShell logging disabled → undetected attack activity
//   - SMBv1 enabled → vulnerable to EternalBlue and other exploits
//
// # PReg Binary Format
//
// Registry.pol uses the "PReg" format, a proprietary binary format created by Microsoft.
//
// File Structure:
//
//	[Header] [Entry1] [Entry2] ... [EntryN]
//
// Header (8 bytes):
//
//	Offset | Size | Field    | Value               | Description
//	-------|------|----------|---------------------|---------------------------
//	0      | 4    | Magic    | "PReg" (0x50526567) | Format identifier (ASCII)
//	4      | 4    | Version  | 0x00000001 (LE)     | Format version (always 1)
//
// Entry Structure (variable length):
//
//	[bracket][key][null][semicolon][valueName][null][semicolon][type][semicolon][size][semicolon][data][bracket]
//
// Entry Fields (all in UTF-16LE encoding):
//
//	Field      | Format     | Example (UTF-16LE bytes)
//	-----------|------------|------------------------------------------
//	[          | 0x5B 0x00  | Opening bracket delimiter
//	key        | UTF-16LE   | "Software\Microsoft\Windows\...\0\0"
//	;          | 0x3B 0x00  | Semicolon delimiter
//	valueName  | UTF-16LE   | "RequireSecuritySignature\0\0"
//	;          | 0x3B 0x00  | Semicolon delimiter
//	type       | DWORD (LE) | 0x04000000 (REG_DWORD)
//	;          | 0x3B 0x00  | Semicolon delimiter
//	size       | DWORD (LE) | 0x04000000 (4 bytes for DWORD)
//	;          | 0x3B 0x00  | Semicolon delimiter
//	data       | Raw bytes  | 0x01000000 (DWORD value = 1)
//	]          | 0x5D 0x00  | Closing bracket delimiter
//
// # Registry Value Types (MS-DTYP Section 2.3.9)
//
//	Type ID | Name             | Description
//	--------|------------------|----------------------------------------------
//	0       | REG_NONE         | No type
//	1       | REG_SZ           | Null-terminated UTF-16LE string
//	2       | REG_EXPAND_SZ    | Null-terminated UTF-16LE string with env vars
//	3       | REG_BINARY       | Raw binary data
//	4       | REG_DWORD        | 32-bit little-endian integer (most common)
//	5       | REG_DWORD_BE     | 32-bit big-endian integer (rare)
//	7       | REG_MULTI_SZ     | Multiple null-terminated UTF-16LE strings
//	11      | REG_QWORD        | 64-bit little-endian integer
//
// # UTF-16LE Encoding
//
// All strings and delimiters use UTF-16LE (Little Endian) encoding:
//   - ASCII 'A' → 0x41 0x00
//   - ASCII '[' → 0x5B 0x00
//   - ASCII ';' → 0x3B 0x00
//   - Null terminator → 0x00 0x00
//
// This means every ASCII character takes 2 bytes, and string parsing must advance by 2 bytes per character.
//
// # Security-Relevant Registry Keys Monitored
//
// SMB Server Signing:
//   - Key: HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters
//   - Value: RequireSecuritySignature (DWORD)
//   - 0 = disabled (vulnerable to relay), 1 = enabled (secure)
//
// SMB Client Signing:
//   - Key: HKLM\System\CurrentControlSet\Services\LanmanWorkstation\Parameters
//   - Value: RequireSecuritySignature (DWORD)
//   - 0 = disabled, 1 = enabled
//
// LDAP Server Signing:
//   - Key: HKLM\System\CurrentControlSet\Services\NTDS\Parameters
//   - Value: LDAPServerIntegrity (DWORD)
//   - 0 = none, 1 = negotiate, 2 = require (recommended)
//
// LDAP Channel Binding:
//   - Key: HKLM\System\CurrentControlSet\Services\NTDS\Parameters
//   - Value: LDAPEnforceChannelBinding (DWORD)
//   - 0 = never, 1 = when supported, 2 = always (recommended)
//
// SMBv1 Protocol:
//   - Key: HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters
//   - Value: SMB1 (DWORD)
//   - 0 = disabled (secure), 1 = enabled (vulnerable to EternalBlue)
//
// PowerShell Script Block Logging:
//   - Key: HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
//   - Value: EnableScriptBlockLogging (DWORD)
//   - 0 = disabled (attacks undetected), 1 = enabled (logs all script blocks)
//
// PowerShell Module Logging:
//   - Key: HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
//   - Value: EnableModuleLogging (DWORD)
//   - 0 = disabled, 1 = enabled (logs cmdlet execution)
//
// Security Event Log Size:
//   - Key: HKLM\Software\Policies\Microsoft\Windows\EventLog\Security
//   - Value: MaxSize (DWORD, in KB)
//   - Recommended: ≥ 1048576 (1 GB) for adequate forensic capacity
//
// # Parsing Algorithm
//
//  1. Verify PReg magic header and version
//  2. For each entry starting at offset 8:
//     a. Find opening bracket '[' (UTF-16LE 0x5B 0x00)
//     b. Read null-terminated UTF-16LE key string
//     c. Skip semicolon delimiter ';' (0x3B 0x00)
//     d. Read null-terminated UTF-16LE value name
//     e. Skip semicolon delimiter
//     f. Read 4-byte type field (little-endian DWORD)
//     g. Skip semicolon delimiter
//     h. Read 4-byte size field (little-endian DWORD)
//     i. Skip semicolon delimiter
//     j. Read 'size' bytes of data
//     k. Find closing bracket ']' (UTF-16LE 0x5D 0x00)
//  3. Decode data based on type (DWORD, SZ, etc.)
//
// # Error Handling
//
// Parser is defensive against malformed files:
//   - Validates header magic and size
//   - Bounds-checks all array accesses
//   - Handles truncated entries gracefully
//   - Skips entries with invalid structure
//   - Returns partial results if some entries are valid
//
// # References
//
// - Group Policy Registry Preference Extension Documentation
// - MS-DTYP: Windows Data Types (Registry Value Types)
// - MS-GPO: Group Policy: Core Protocol
package smb

import (
	"encoding/binary"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
)

// RegistryPolEntry represents a single entry from Registry.pol
type RegistryPolEntry struct {
	Key       string
	ValueName string
	Type      uint32
	Data      []byte
}

// ParseRegistryPol parses a Registry.pol file and extracts security-relevant settings
func ParseRegistryPol(data []byte) *audit.RegistrySettings {
	entries := parseRegistryPolEntries(data)
	if len(entries) == 0 {
		return nil
	}

	rs := &audit.RegistrySettings{}
	found := false

	for _, entry := range entries {
		keyLower := strings.ToLower(entry.Key)
		valueLower := strings.ToLower(entry.ValueName)

		switch {
		// SMB Server Signing: RequireSecuritySignature
		case strings.Contains(keyLower, "lanmanserver") && strings.Contains(keyLower, "parameters") &&
			valueLower == "requiresecuritysignature":
			if v, ok := getDWORDValue(entry); ok {
				rs.RequireSMBSigningServer = &v
				found = true
			}

		// SMB Client Signing: RequireSecuritySignature
		case strings.Contains(keyLower, "lanmanworkstation") && strings.Contains(keyLower, "parameters") &&
			valueLower == "requiresecuritysignature":
			if v, ok := getDWORDValue(entry); ok {
				rs.RequireSMBSigningClient = &v
				found = true
			}

		// LDAP Server Integrity
		case strings.Contains(keyLower, "ntds") && strings.Contains(keyLower, "parameters") &&
			valueLower == "ldapserverintegrity":
			if v, ok := getDWORDValue(entry); ok {
				rs.LDAPServerIntegrity = &v
				found = true
			}

		// LDAP Channel Binding
		case strings.Contains(keyLower, "ntds") && strings.Contains(keyLower, "parameters") &&
			valueLower == "ldapenforcechannelbinding":
			if v, ok := getDWORDValue(entry); ok {
				rs.LDAPChannelBinding = &v
				found = true
			}

		// SMBv1 (various paths)
		case strings.Contains(keyLower, "lanmanserver") && strings.Contains(keyLower, "parameters") &&
			valueLower == "smb1":
			if v, ok := getDWORDValue(entry); ok {
				rs.SMB1Enabled = &v
				found = true
			}

		// PowerShell Script Block Logging
		case strings.Contains(keyLower, "powershell") && strings.Contains(keyLower, "scriptblocklogging") &&
			valueLower == "enablescriptblocklogging":
			if v, ok := getDWORDValue(entry); ok {
				rs.PSScriptBlockLogging = &v
				found = true
			}

		// PowerShell Module Logging
		case strings.Contains(keyLower, "powershell") && strings.Contains(keyLower, "modulelogging") &&
			valueLower == "enablemodulelogging":
			if v, ok := getDWORDValue(entry); ok {
				rs.PSModuleLogging = &v
				found = true
			}

		// PowerShell Transcription
		case strings.Contains(keyLower, "powershell") && strings.Contains(keyLower, "transcription") &&
			valueLower == "enabletranscripting":
			if v, ok := getDWORDValue(entry); ok {
				rs.PSTranscriptionEnabled = &v
				found = true
			}

		// Security Event Log Max Size
		case strings.Contains(keyLower, "eventlog") && strings.Contains(keyLower, "security") &&
			valueLower == "maxsize":
			if v, ok := getDWORDValue(entry); ok {
				rs.SecurityLogMaxSizeKB = &v
				found = true
			}

		// LLMNR
		case strings.Contains(keyLower, "dnsclient") && valueLower == "enablemulticast":
			if v, ok := getDWORDValue(entry); ok {
				rs.LLMNRDisabled = &v
				found = true
			}

		// Kerberos Armoring DC (KDC FAST support)
		case strings.Contains(keyLower, "kdc") && (valueLower == "supportedenctypes" || valueLower == "supportedencryptiontypes"):
			if v, ok := getDWORDValue(entry); ok {
				rs.KerberosArmoringDC = &v
				found = true
			}

		// Kerberos Armoring Client (FAST required)
		case strings.Contains(keyLower, "kerberos") && strings.Contains(keyLower, "parameters") &&
			valueLower == "requirefast":
			if v, ok := getDWORDValue(entry); ok {
				rs.KerberosArmoringClient = &v
				found = true
			}

		// Terminal Services / RDP
		case strings.Contains(keyLower, "terminal services") && valueLower == "fdenytsconnections":
			if v, ok := getDWORDValue(entry); ok {
				rs.RDPDenyConnections = &v
				found = true
			}
		case strings.Contains(keyLower, "terminal services") && valueLower == "securitylayer":
			if v, ok := getDWORDValue(entry); ok {
				rs.RDPSecurityLayer = &v
				found = true
			}
		case strings.Contains(keyLower, "terminal services") && valueLower == "userauthentication":
			if v, ok := getDWORDValue(entry); ok {
				rs.RDPNLA = &v
				found = true
			}

		// Hardened UNC Paths
		case strings.Contains(keyLower, "networkprovider") && strings.Contains(keyLower, "hardenedpaths"):
			if s := getStringValue(entry); s != "" {
				if strings.Contains(valueLower, "netlogon") {
					rs.HardenedPathsNetlogon = &s
					found = true
				} else if strings.Contains(valueLower, "sysvol") {
					rs.HardenedPathsSysvol = &s
					found = true
				}
			}

		// NetCease session hardening
		case strings.Contains(keyLower, "lanmanserver") && strings.Contains(keyLower, "defaultsecurity") &&
			strings.Contains(valueLower, "srvsvc"):
			if v, ok := getDWORDValue(entry); ok {
				rs.NetSessionHardening = &v
				found = true
			}

		// Defender ASR
		case strings.Contains(keyLower, "windows defender") && strings.Contains(keyLower, "asr") &&
			valueLower == "exploitguard_asr_rules":
			if v, ok := getDWORDValue(entry); ok {
				rs.DefenderASREnabled = &v
				found = true
			}

		// Firewall outbound
		case strings.Contains(keyLower, "windowsfirewall") && strings.Contains(keyLower, "domainprofile") &&
			valueLower == "defaultoutboundaction":
			if v, ok := getDWORDValue(entry); ok {
				rs.FirewallOutboundAction = &v
				found = true
			}

		// WDigest
		case strings.Contains(keyLower, "wdigest") && valueLower == "uselogoncredential":
			if v, ok := getDWORDValue(entry); ok {
				rs.WDigestUseLogonCredential = &v
				found = true
			}

		// LSA Protection (RunAsPPL)
		case strings.Contains(keyLower, "lsa") && !strings.Contains(keyLower, "lsass") && valueLower == "runasppl":
			if v, ok := getDWORDValue(entry); ok {
				rs.LSARunAsPPL = &v
				found = true
			}

		// Credential Guard
		case strings.Contains(keyLower, "deviceguard") && valueLower == "enablevirtualizationbasedsecurity":
			if v, ok := getDWORDValue(entry); ok {
				rs.CredentialGuardEnabled = &v
				found = true
			}

		// NTLMv2
		case strings.Contains(keyLower, "lsa") && !strings.Contains(keyLower, "lsass") && valueLower == "lmcompatibilitylevel":
			if v, ok := getDWORDValue(entry); ok {
				rs.LmCompatibilityLevel = &v
				found = true
			}

		// Cached Logons
		case strings.Contains(keyLower, "winlogon") && valueLower == "cachedlogonscount":
			if v, ok := getDWORDValue(entry); ok {
				rs.CachedLogonsCount = &v
				found = true
			}

		// Restrict Remote SAM
		case strings.Contains(keyLower, "lsa") && !strings.Contains(keyLower, "lsass") && valueLower == "restrictremotesam":
			if s := getStringValue(entry); s != "" {
				rs.RestrictRemoteSAM = &s
				found = true
			}

		// WSUS
		case strings.Contains(keyLower, "windowsupdate") && valueLower == "wuserver":
			if s := getStringValue(entry); s != "" {
				rs.WUServer = &s
				found = true
			}

		// PrintNightmare / Point and Print
		case strings.Contains(keyLower, "pointandprint") && valueLower == "nowarningnoelevationoninstall":
			if v, ok := getDWORDValue(entry); ok {
				rs.PointAndPrintNoElevation = &v
				found = true
			}

		// Zerologon enforcement
		case strings.Contains(keyLower, "netlogon") && strings.Contains(keyLower, "parameters") &&
			valueLower == "fullsecurechannelprotection":
			if v, ok := getDWORDValue(entry); ok {
				rs.ZerologonEnforcement = &v
				found = true
			}

		// BitLocker
		case strings.Contains(keyLower, "fve") && valueLower == "requiredeviceencryption":
			if v, ok := getDWORDValue(entry); ok {
				rs.BitLockerRequired = &v
				found = true
			}

		// Folder Options: DefaultFileTypeRisk
		case strings.Contains(keyLower, "associations") && valueLower == "defaultfiletyperisk":
			if v, ok := getDWORDValue(entry); ok {
				rs.FolderOptionsDefaultFileTypeRisk = &v
				found = true
			}

		// Folder Options: LowRiskFileTypes
		case strings.Contains(keyLower, "associations") && valueLower == "lowriskfiletypes":
			if s := getStringValue(entry); s != "" {
				rs.FolderOptionsLowRiskFileTypes = &s
				found = true
			}

		// v3.1.17 — HVCI / Hypervisor-Enforced Code Integrity
		case strings.Contains(keyLower, "deviceguard") && valueLower == "hypervisorenforcedcodeintegrity":
			if v, ok := getDWORDValue(entry); ok {
				rs.HVCIEnabled = &v
				found = true
			}

		// v3.1.17 — Credential Guard scope (LsaCfgFlags). 0=off, 1=enabled, 2=enabled+UEFI lock.
		case strings.Contains(keyLower, "lsa") && !strings.Contains(keyLower, "lsass") && valueLower == "lsacfgflags":
			if v, ok := getDWORDValue(entry); ok {
				rs.LsaCfgFlags = &v
				found = true
			}

		// v3.1.17 — Device Guard / VBS UEFI lock
		case strings.Contains(keyLower, "deviceguard") && valueLower == "requireplatformsecurityfeatures":
			if v, ok := getDWORDValue(entry); ok {
				rs.DeviceGuardCodeIntegrityPolicyEnforcement = &v
				found = true
			}

		// v3.1.17 — Configurable Code Integrity policy file (WDAC) marker
		case strings.Contains(keyLower, "codeintegrity") && valueLower == "configcipolicyfilepath":
			if s := getStringValue(entry); s != "" {
				rs.DeviceGuardConfigCIPolicyFilePath = &s
				found = true
			}

		// v3.1.17 — NTLM outbound blocking (PA-099 R73 / R74+)
		case strings.Contains(keyLower, "msv1_0") && valueLower == "restrictsendingntlmtraffic":
			if v, ok := getDWORDValue(entry); ok {
				rs.RestrictSendingNTLMTraffic = &v
				found = true
			}
		case strings.Contains(keyLower, "msv1_0") && valueLower == "restrictreceivingntlmtraffic":
			if v, ok := getDWORDValue(entry); ok {
				rs.RestrictReceivingNTLMTraffic = &v
				found = true
			}

		// v3.1.18 — RDP encryption (ANSSI PA-099 R79)
		case strings.Contains(keyLower, "terminal services") && valueLower == "minencryptionlevel":
			if v, ok := getDWORDValue(entry); ok {
				rs.RDPMinEncryptionLevel = &v
				found = true
			}
		case strings.Contains(keyLower, "terminal services") && valueLower == "fencryptrpctraffic":
			if v, ok := getDWORDValue(entry); ok {
				rs.RDPEncryptRPCTraffic = &v
				found = true
			}
		}
	}

	if !found {
		return nil
	}
	return rs
}

// getStringValue extracts a string from a REG_SZ registry entry.
func getStringValue(entry RegistryPolEntry) string {
	if entry.Type != 1 && entry.Type != 2 { // REG_SZ or REG_EXPAND_SZ
		return ""
	}
	if len(entry.Data) < 2 {
		return ""
	}
	// Decode UTF-16LE string
	var sb strings.Builder
	for i := 0; i+1 < len(entry.Data); i += 2 {
		lo := entry.Data[i]
		hi := entry.Data[i+1]
		if lo == 0 && hi == 0 {
			break
		}
		ch := rune(lo) | rune(hi)<<8
		sb.WriteRune(ch)
	}
	return sb.String()
}

// parseRegistryPolEntries parses the binary Registry.pol format and extracts all entries.
//
// Validates PReg header (magic "PReg" + version 1), then iterates through entries
// starting at offset 8. Each entry is parsed with parseOneEntry() which handles
// UTF-16LE string parsing and delimiter detection.
//
// Returns all successfully parsed entries. Stops at first unparseable entry or EOF.
func parseRegistryPolEntries(data []byte) []RegistryPolEntry {
	// Minimum size: 8 bytes header
	if len(data) < 8 {
		return nil
	}

	// Verify PReg header: "PReg" in ASCII
	if string(data[:4]) != "PReg" {
		return nil
	}

	// Version: should be 1
	// data[4:8] is version, we skip it

	var entries []RegistryPolEntry
	pos := 8

	for pos < len(data) {
		entry, newPos, ok := parseOneEntry(data, pos)
		if !ok {
			break
		}
		entries = append(entries, entry)
		pos = newPos
	}

	return entries
}

// parseOneEntry parses a single Registry.pol entry from the binary data stream.
//
// Entry Structure (UTF-16LE encoding):
//
//	[key\0;valueName\0;type;size;data]
//
// Parsing Steps:
//  1. Find '[' (0x5B 0x00) - entry start marker
//  2. Read key: null-terminated UTF-16LE string (e.g., "Software\Microsoft\...")
//  3. Find ';' (0x3B 0x00) - field separator
//  4. Read valueName: null-terminated UTF-16LE string (e.g., "RequireSecuritySignature")
//  5. Find ';' - field separator
//  6. Read type: 4-byte little-endian DWORD (e.g., 4 = REG_DWORD)
//  7. Find ';' - field separator
//  8. Read size: 4-byte little-endian DWORD (byte count of data field)
//  9. Find ';' - field separator
//  10. Read data: 'size' raw bytes (interpretation depends on type)
//  11. Find ']' (0x5D 0x00) - entry end marker
//
// Example Entry Bytes (SMB signing enabled):
//
//	[0x5B 0x00] // '['
//	[UTF-16LE: "System\CurrentControlSet\Services\LanmanServer\Parameters\0\0"]
//	[0x3B 0x00] // ';'
//	[UTF-16LE: "RequireSecuritySignature\0\0"]
//	[0x3B 0x00] // ';'
//	[0x04 0x00 0x00 0x00] // type = 4 (REG_DWORD)
//	[0x3B 0x00] // ';'
//	[0x04 0x00 0x00 0x00] // size = 4 bytes
//	[0x3B 0x00] // ';'
//	[0x01 0x00 0x00 0x00] // data = 1 (enabled)
//	[0x5D 0x00] // ']'
//
// Returns:
//   - entry: Parsed registry entry
//   - newPos: Position after this entry (for next entry parsing)
//   - ok: true if parse successful, false if malformed/EOF
func parseOneEntry(data []byte, pos int) (RegistryPolEntry, int, bool) {
	var entry RegistryPolEntry

	// Find opening bracket '[' (UTF-16LE: 0x5B 0x00)
	pos = findUTF16Char(data, pos, 0x5B) // '['
	if pos < 0 {
		return entry, len(data), false
	}
	pos += 2 // Skip '['

	// Read key (UTF-16LE null-terminated string)
	key, newPos := readUTF16String(data, pos)
	if newPos < 0 {
		return entry, len(data), false
	}
	entry.Key = key
	pos = newPos

	// Skip ';' delimiter
	pos = findUTF16Char(data, pos, 0x3B) // ';'
	if pos < 0 {
		return entry, len(data), false
	}
	pos += 2

	// Read value name
	valueName, newPos2 := readUTF16String(data, pos)
	if newPos2 < 0 {
		return entry, len(data), false
	}
	entry.ValueName = valueName
	pos = newPos2

	// Skip ';' delimiter
	pos = findUTF16Char(data, pos, 0x3B)
	if pos < 0 {
		return entry, len(data), false
	}
	pos += 2

	// Read type (4 bytes, little-endian DWORD)
	if pos+4 > len(data) {
		return entry, len(data), false
	}
	entry.Type = binary.LittleEndian.Uint32(data[pos : pos+4])
	pos += 4

	// Skip ';' delimiter
	pos = findUTF16Char(data, pos, 0x3B)
	if pos < 0 {
		return entry, len(data), false
	}
	pos += 2

	// Read size (4 bytes)
	if pos+4 > len(data) {
		return entry, len(data), false
	}
	size := int(binary.LittleEndian.Uint32(data[pos : pos+4]))
	pos += 4

	// Skip ';' delimiter
	pos = findUTF16Char(data, pos, 0x3B)
	if pos < 0 {
		return entry, len(data), false
	}
	pos += 2

	// Read data
	if pos+size > len(data) {
		size = len(data) - pos
	}
	if size > 0 {
		entry.Data = make([]byte, size)
		copy(entry.Data, data[pos:pos+size])
	}
	pos += size

	// Find closing bracket ']'
	closeBracket := findUTF16Char(data, pos, 0x5D) // ']'
	if closeBracket >= 0 {
		pos = closeBracket + 2
	}

	return entry, pos, true
}

// findUTF16Char searches for a specific ASCII character encoded in UTF-16LE.
//
// UTF-16LE encoding: ASCII character X becomes bytes [X, 0x00]
// Example: ';' (ASCII 0x3B) → [0x3B, 0x00] in UTF-16LE
//
// Advances by 2 bytes per iteration (UTF-16LE character width).
// Returns byte offset of character, or -1 if not found.
func findUTF16Char(data []byte, pos int, char byte) int {
	for i := pos; i+1 < len(data); i += 2 {
		if data[i] == char && data[i+1] == 0x00 {
			return i
		}
	}
	return -1
}

// readUTF16String reads a null-terminated UTF-16LE encoded string from the byte stream.
//
// UTF-16LE Decoding:
//   - Reads 2 bytes per character (little-endian)
//   - Low byte first, high byte second
//   - Null terminator: [0x00, 0x00] (2-byte null)
//
// Example: "SMB" in UTF-16LE
//   - 'S' = [0x53, 0x00] → rune(0x0053)
//   - 'M' = [0x4D, 0x00] → rune(0x004D)
//   - 'B' = [0x42, 0x00] → rune(0x0042)
//   - null = [0x00, 0x00] → stop
//
// Returns:
//   - string: Decoded Go string (UTF-8 internally)
//   - newPos: Position after null terminator (ready for next field)
//   - newPos=-1 if no null terminator found (truncated/malformed)
func readUTF16String(data []byte, pos int) (string, int) {
	var sb strings.Builder
	for i := pos; i+1 < len(data); i += 2 {
		lo := data[i]
		hi := data[i+1]
		if lo == 0 && hi == 0 {
			return sb.String(), i + 2
		}
		ch := rune(lo) | rune(hi)<<8
		sb.WriteRune(ch)
	}
	return sb.String(), -1
}

// getDWORDValue extracts a 32-bit integer from a REG_DWORD registry entry.
//
// REG_DWORD (type 4):
//   - 4 bytes of data (little-endian)
//   - Represents integers, booleans (0/1), flags, sizes
//
// Example: RequireSecuritySignature = 1
//   - Type: 4 (REG_DWORD)
//   - Data: [0x01, 0x00, 0x00, 0x00] → integer value 1
//
// Returns (value, true) if entry is REG_DWORD and has valid data.
// Returns (0, false) if entry is not REG_DWORD or data is too short.
func getDWORDValue(entry RegistryPolEntry) (int, bool) {
	if entry.Type != 4 { // REG_DWORD
		return 0, false
	}
	if len(entry.Data) < 4 {
		return 0, false
	}
	return int(binary.LittleEndian.Uint32(entry.Data[:4])), true
}
