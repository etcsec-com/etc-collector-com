// Package ldap provides LDAP client functionality
//
// This file implements Windows Security Descriptor & ACL parsing for Active Directory security analysis.
//
// # Security Descriptors Overview
//
// Every Active Directory object has an ntSecurityDescriptor attribute containing binary access control
// data that determines who can read, modify, or delete the object. This parser extracts ACL entries
// from these binary descriptors to identify dangerous permissions that enable privilege escalation.
//
// # Why This Matters for Security
//
// Excessive ACL permissions are a primary privilege escalation vector in Active Directory:
//   - GenericAll on user → reset password, add to groups
//   - WriteDACL on object → grant self GenericAll
//   - WriteOwner on object → take ownership, then modify DACL
//   - DS-Replication-Get-Changes + DS-Replication-Get-Changes-All → DCSync attack
//
// # Binary Format (MS-DTYP Section 2.4.6)
//
// Security Descriptor Structure (minimum 20 bytes):
//
//   Offset | Size | Field           | Description
//   -------|------|-----------------|------------------------------------------
//   0      | 1    | Revision        | Structure version (always 1)
//   1      | 1    | Sbz1            | Padding (should be zero)
//   2      | 2    | Control         | Control flags (DACL present, etc.)
//   4      | 4    | OffsetOwner     | Byte offset to owner SID (LE)
//   8      | 4    | OffsetGroup     | Byte offset to group SID (LE)
//   12     | 4    | OffsetSacl      | Byte offset to SACL (audit) (LE)
//   16     | 4    | OffsetDacl      | Byte offset to DACL (permissions) (LE)
//
// DACL (Discretionary ACL) Structure:
//
//   Offset | Size | Field           | Description
//   -------|------|-----------------|------------------------------------------
//   0      | 1    | AclRevision     | ACL version (2 or 4)
//   1      | 1    | Sbz1            | Padding
//   2      | 2    | AclSize         | Total ACL size in bytes (LE)
//   4      | 2    | AceCount        | Number of ACE entries (LE)
//   6      | 2    | Sbz2            | Padding
//   8      | N    | ACEs[]          | Array of ACE structures
//
// ACE (Access Control Entry) Structure (Standard, 8+ bytes):
//
//   Offset | Size | Field           | Description
//   -------|------|-----------------|------------------------------------------
//   0      | 1    | AceType         | 0x00=ALLOWED, 0x05=ALLOWED_OBJECT
//   1      | 1    | AceFlags        | Inheritance flags
//   2      | 2    | AceSize         | Total ACE size in bytes (LE)
//   4      | 4    | AccessMask      | Permission bitmask (LE)
//   8      | N    | SID             | Trustee SID (variable length)
//
// ACE Object Structure (for ALLOWED_OBJECT type, 12+ bytes before SID):
//
//   Offset | Size | Field           | Description
//   -------|------|-----------------|------------------------------------------
//   0-7    | 8    | (Standard ACE)  | Type, flags, size, access mask
//   8      | 4    | ObjectFlags     | Indicates presence of GUIDs (LE)
//   12     | 16   | ObjectType      | GUID (if ACE_OBJECT_TYPE_PRESENT)
//   28     | 16   | InheritedType   | GUID (if ACE_INHERITED_OBJECT_TYPE_PRESENT)
//   44     | N    | SID             | Trustee SID (variable length)
//
// SID (Security Identifier) Structure (8+ bytes):
//
//   Offset | Size | Field                | Description
//   -------|------|----------------------|-----------------------------------
//   0      | 1    | Revision             | SID version (always 1)
//   1      | 1    | SubAuthorityCount    | Number of sub-authorities (N)
//   2      | 6    | IdentifierAuthority  | Authority value (big-endian!)
//   8      | 4*N  | SubAuthorities[]     | Array of N sub-auths (LE)
//
// Example: Domain Admins SID = S-1-5-21-<domain-id>-512
//   - Revision: 1
//   - SubAuthorityCount: 5
//   - IdentifierAuthority: 5 (NT Authority)
//   - SubAuthorities: [21, <domain-id1>, <domain-id2>, <domain-id3>, 512]
//
// # Access Mask Bits (MS-DTYP Section 2.4.3)
//
// Generic Rights (upper 4 bits):
//   0x10000000 - GENERIC_ALL (full control)
//   0x20000000 - GENERIC_EXECUTE
//   0x40000000 - GENERIC_WRITE
//   0x80000000 - GENERIC_READ
//
// Standard Rights (bits 16-23):
//   0x00010000 - DELETE
//   0x00020000 - READ_CONTROL (read security descriptor)
//   0x00040000 - WRITE_DACL (modify permissions)
//   0x00080000 - WRITE_OWNER (take ownership)
//   0x00100000 - SYNCHRONIZE
//
// Specific Rights (bits 0-15):
//   0x00000001 - ACTRL_DS_CREATE_CHILD
//   0x00000002 - ACTRL_DS_DELETE_CHILD
//   0x00000004 - ACTRL_DS_LIST
//   0x00000008 - ACTRL_DS_SELF (modify group membership)
//   0x00000010 - ACTRL_DS_READ_PROP
//   0x00000020 - ACTRL_DS_WRITE_PROP
//   0x00000040 - ACTRL_DS_DELETE_TREE
//   0x00000080 - ACTRL_DS_LIST_OBJECT
//   0x00000100 - ACTRL_DS_CONTROL_ACCESS (extended rights)
//
// # Extended Rights (CONTROL_ACCESS + ObjectType GUID)
//
// Common Extended Rights GUIDs:
//   - DS-Replication-Get-Changes: 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2
//   - DS-Replication-Get-Changes-All: 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2
//   - User-Force-Change-Password: 00299570-246d-11d0-a768-00aa006e0529
//   - Self-Membership: bf9679c0-0de6-11d0-a285-00aa003049e2
//
// # References
//
// - MS-DTYP: Windows Data Types (Security Descriptor, ACL, ACE, SID structures)
//   https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/
// - MS-ADTS: Active Directory Technical Specification (extended rights)
//   https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/

package ldap

import (
	"encoding/binary"
	"fmt"

	"github.com/etcsec-com/etc-collector/pkg/types"
)

// ACE Types
const (
	aceTypeAccessAllowed       = 0x00
	aceTypeAccessDenied        = 0x01
	aceTypeSystemAudit         = 0x02
	aceTypeAccessAllowedObject = 0x05
	aceTypeAccessDeniedObject  = 0x06
	aceTypeSystemAuditObject   = 0x07
)

// ACE Object Flags
const (
	aceObjectTypePresent          = 0x01
	aceInheritedObjectTypePresent = 0x02
)

// Security Descriptor Control Flags
const (
	seDaclPresent = 0x0004
)

// ParseOwnerSID extracts the Owner SID from a binary security descriptor.
// The Owner SID is at the offset specified in bytes 4-7 of the SD header.
// In Active Directory, the owner of an object can modify the DACL (grant self GenericAll),
// making ownership a privilege escalation primitive (Owns edge in BloodHound).
func ParseOwnerSID(securityDescriptor []byte) string {
	if len(securityDescriptor) < 20 {
		return ""
	}

	defer func() {
		if r := recover(); r != nil {
			// Silently fail
		}
	}()

	ownerOffset := binary.LittleEndian.Uint32(securityDescriptor[4:8])
	if ownerOffset == 0 || int(ownerOffset) >= len(securityDescriptor) {
		return ""
	}

	sid := parseSID(securityDescriptor, int(ownerOffset))
	if sid == "S-1-0-0" {
		return ""
	}
	return sid
}

// ParseSecurityDescriptor parses ntSecurityDescriptor binary data into ACL entries
func ParseSecurityDescriptor(securityDescriptor []byte, objectDN string) []types.ACLEntry {
	if len(securityDescriptor) < 20 {
		return nil
	}

	defer func() {
		// Recover from any panics during parsing
		if r := recover(); r != nil {
			// Silently fail - many objects may have unusual security descriptors
		}
	}()

	// Parse Security Descriptor header
	// Byte 0: Revision
	// Byte 1: Sbz1 (padding)
	// Bytes 2-3: Control flags (LE)
	// Bytes 4-7: OffsetOwner
	// Bytes 8-11: OffsetGroup
	// Bytes 12-15: OffsetSacl
	// Bytes 16-19: OffsetDacl

	control := binary.LittleEndian.Uint16(securityDescriptor[2:4])

	// Check if DACL is present
	if (control & seDaclPresent) == 0 {
		return nil
	}

	// Get DACL offset
	daclOffset := binary.LittleEndian.Uint32(securityDescriptor[16:20])
	if daclOffset == 0 || int(daclOffset) >= len(securityDescriptor) {
		return nil
	}

	// Parse DACL
	dacl := securityDescriptor[daclOffset:]
	if len(dacl) < 8 {
		return nil
	}

	// ACL Header:
	// Byte 0: AclRevision
	// Byte 1: Sbz1
	// Bytes 2-3: AclSize (LE)
	// Bytes 4-5: AceCount (LE)
	// Bytes 6-7: Sbz2

	aclSize := binary.LittleEndian.Uint16(dacl[2:4])
	aceCount := binary.LittleEndian.Uint16(dacl[4:6])

	if int(aclSize) > len(dacl) {
		aclSize = uint16(len(dacl))
	}

	var aclEntries []types.ACLEntry

	// Parse each ACE
	aceOffset := 8 // ACL header is 8 bytes
	for i := 0; i < int(aceCount); i++ {
		if aceOffset >= int(aclSize) {
			break
		}

		ace := parseACE(dacl, aceOffset, objectDN)
		if ace != nil {
			aclEntries = append(aclEntries, *ace)
		}

		// Move to next ACE (get size from ACE header)
		if aceOffset+4 > len(dacl) {
			break
		}
		aceSize := binary.LittleEndian.Uint16(dacl[aceOffset+2 : aceOffset+4])
		if aceSize == 0 {
			break
		}
		aceOffset += int(aceSize)
	}

	return aclEntries
}

// parseACE parses a single Access Control Entry from the DACL.
//
// ACE Structure:
//   - Standard ACE: type(1) + flags(1) + size(2) + mask(4) + SID(N)
//   - Object ACE: + objectFlags(4) + optional ObjectType GUID(16) + optional InheritedObjectType GUID(16) + SID(N)
//
// Object ACEs (type 0x05) include optional GUIDs that specify:
//   - ObjectType: Which extended right or property this ACE applies to (e.g., "Reset Password")
//   - InheritedObjectType: Which object class this ACE applies to (e.g., "User objects only")
//
// Security Relevance:
//   - ACCESS_ALLOWED (0x00): Grants permissions to trustee
//   - ACCESS_ALLOWED_OBJECT (0x05): Grants permissions with GUID specificity (extended rights)
//   - We skip DENIED ACEs as they don't enable privilege escalation (defensive only)
//
// Returns nil if ACE is not exploitable for privilege escalation analysis.
func parseACE(dacl []byte, offset int, objectDN string) *types.ACLEntry {
	if offset+8 > len(dacl) {
		return nil
	}

	aceType := dacl[offset]
	aceFlags := dacl[offset+1]
	accessMask := binary.LittleEndian.Uint32(dacl[offset+4 : offset+8])
	// INHERITED_ACE flag (0x10) — required by v3.1.29 §4 to distinguish
	// explicit ACEs (revoke at the target) from inherited ones (revoke at
	// the parent container or block inheritance). Critical for remediation.
	const aceFlagInheritedAce = 0x10
	isInherited := (aceFlags & aceFlagInheritedAce) != 0

	// We only care about ACCESS_ALLOWED and ACCESS_ALLOWED_OBJECT ACEs
	if aceType != aceTypeAccessAllowed && aceType != aceTypeAccessAllowedObject {
		return nil
	}

	sidOffset := 8 // Standard ACE: type(1) + flags(1) + size(2) + mask(4)
	var objectType string

	// Handle Object ACEs (have optional GUIDs before SID)
	if aceType == aceTypeAccessAllowedObject {
		if offset+12 > len(dacl) {
			return nil
		}
		objectFlags := binary.LittleEndian.Uint32(dacl[offset+8 : offset+12])
		sidOffset = 12 // Object ACE: + flags(4)

		// If ACE_OBJECT_TYPE_PRESENT flag is set, there's a GUID
		if (objectFlags & aceObjectTypePresent) != 0 {
			if offset+sidOffset+16 > len(dacl) {
				return nil
			}
			objectType = parseGUID(dacl, offset+sidOffset)
			sidOffset += 16 // GUID is 16 bytes
		}

		// If ACE_INHERITED_OBJECT_TYPE_PRESENT flag is set, skip inherited GUID
		if (objectFlags & aceInheritedObjectTypePresent) != 0 {
			sidOffset += 16
		}
	}

	// Parse SID
	if offset+sidOffset >= len(dacl) {
		return nil
	}
	sid := parseSID(dacl, offset+sidOffset)

	return &types.ACLEntry{
		ObjectDN:    objectDN,
		Trustee:     sid,
		AccessMask:  int(accessMask),
		AceType:     aceTypeToString(aceType),
		ObjectType:  objectType,
		IsInherited: isInherited,
	}
}

// parseSID parses a Windows Security Identifier from binary format to string representation.
//
// SID Binary Format:
//   - Revision (1 byte): Always 1
//   - SubAuthorityCount (1 byte): Number of sub-authorities (0-15)
//   - IdentifierAuthority (6 bytes): Big-endian 48-bit authority value
//   - SubAuthorities (4*N bytes): N little-endian 32-bit sub-authority values
//
// String Format: S-<revision>-<authority>-<subauth1>-<subauth2>-...-<subauthN>
//
// Examples:
//   - S-1-5-21-123-456-789-512 = Domain Admins (RID 512)
//   - S-1-5-32-544 = Local Administrators
//   - S-1-5-18 = LOCAL_SYSTEM
//
// Note: IdentifierAuthority is big-endian (network byte order) while SubAuthorities are little-endian.
// This mixed endianness is a quirk of the Windows SID format.
func parseSID(buffer []byte, offset int) string {
	if offset+8 > len(buffer) {
		return "S-1-0-0"
	}

	revision := buffer[offset]
	subAuthorityCount := buffer[offset+1]

	// Sanity check
	if subAuthorityCount > 15 || offset+8+int(subAuthorityCount)*4 > len(buffer) {
		return "S-1-0-0"
	}

	// Read identifier authority (6 bytes, big-endian)
	// It's stored as a 48-bit big-endian value
	var identifierAuthority uint64
	for i := 0; i < 6; i++ {
		identifierAuthority = (identifierAuthority << 8) | uint64(buffer[offset+2+i])
	}

	// Build SID string
	sid := fmt.Sprintf("S-%d-%d", revision, identifierAuthority)

	// Read sub-authorities (4 bytes each, little-endian)
	subAuthOffset := offset + 8
	for i := 0; i < int(subAuthorityCount); i++ {
		subAuth := binary.LittleEndian.Uint32(buffer[subAuthOffset : subAuthOffset+4])
		sid += fmt.Sprintf("-%d", subAuth)
		subAuthOffset += 4
	}

	return sid
}

// parseGUID parses a Microsoft GUID from binary format to standard string representation.
//
// GUID Binary Format (16 bytes total, mixed endianness):
//   - Data1 (4 bytes): Little-endian 32-bit integer
//   - Data2 (2 bytes): Little-endian 16-bit integer
//   - Data3 (2 bytes): Little-endian 16-bit integer
//   - Data4 (8 bytes): Big-endian byte array (2 bytes + 6 bytes)
//
// String Format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx (lowercase hex)
//
// Example Extended Rights GUIDs:
//   - 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2 = DS-Replication-Get-Changes (DCSync part 1)
//   - 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2 = DS-Replication-Get-Changes-All (DCSync part 2)
//   - 00299570-246d-11d0-a768-00aa006e0529 = User-Force-Change-Password
//
// These GUIDs appear in Object ACEs to specify which extended right the ACE grants.
func parseGUID(buffer []byte, offset int) string {
	if offset+16 > len(buffer) {
		return "00000000-0000-0000-0000-000000000000"
	}

	// GUID format: Data1 (4 bytes LE) - Data2 (2 bytes LE) - Data3 (2 bytes LE) - Data4 (8 bytes)
	data1 := binary.LittleEndian.Uint32(buffer[offset : offset+4])
	data2 := binary.LittleEndian.Uint16(buffer[offset+4 : offset+6])
	data3 := binary.LittleEndian.Uint16(buffer[offset+6 : offset+8])

	// Data4 is 8 bytes: first 2 bytes + last 6 bytes
	data4High := buffer[offset+8 : offset+10]
	data4Low := buffer[offset+10 : offset+16]

	return fmt.Sprintf("%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		data1, data2, data3,
		data4High[0], data4High[1],
		data4Low[0], data4Low[1], data4Low[2], data4Low[3], data4Low[4], data4Low[5])
}

// aceTypeToString converts ACE type byte to human-readable string.
//
// ACE Types (MS-DTYP Section 2.4.4.1):
//
//	0x00 - ACCESS_ALLOWED: Grants permissions
//	0x01 - ACCESS_DENIED: Denies permissions (checked before ALLOWED)
//	0x02 - SYSTEM_AUDIT: Generates audit logs
//	0x05 - ACCESS_ALLOWED_OBJECT: Grants permissions with GUID specificity
//	0x06 - ACCESS_DENIED_OBJECT: Denies permissions with GUID specificity
//	0x07 - SYSTEM_AUDIT_OBJECT: Generates audit logs with GUID specificity
func aceTypeToString(aceType byte) string {
	switch aceType {
	case aceTypeAccessAllowed:
		return "ACCESS_ALLOWED"
	case aceTypeAccessDenied:
		return "ACCESS_DENIED"
	case aceTypeSystemAudit:
		return "SYSTEM_AUDIT"
	case aceTypeAccessAllowedObject:
		return "ACCESS_ALLOWED_OBJECT"
	case aceTypeAccessDeniedObject:
		return "ACCESS_DENIED_OBJECT"
	case aceTypeSystemAuditObject:
		return "SYSTEM_AUDIT_OBJECT"
	default:
		return fmt.Sprintf("UNKNOWN_%d", aceType)
	}
}
