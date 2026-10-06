package audit

import (
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/etcsec-com/etc-collector/pkg/types"
)

// ParseRBCDTrustees extracts trustee SIDs from a binary security descriptor.
// Used for msDS-AllowedToActOnBehalfOfOtherIdentity (RBCD) and msDS-GroupMSAMembership (gMSA).
//
// Binary format: Security Descriptor → DACL → ACCESS_ALLOWED ACEs → Trustee SIDs
// Reference: MS-DTYP Section 2.4.6
func ParseRBCDTrustees(sd []byte) []string {
	if len(sd) < 20 {
		return nil
	}

	defer func() {
		recover() // Guard against malformed descriptors
	}()

	// Control flags at offset 2-3
	control := binary.LittleEndian.Uint16(sd[2:4])
	if control&0x0004 == 0 { // SE_DACL_PRESENT
		return nil
	}

	// DACL offset at bytes 16-19
	daclOffset := binary.LittleEndian.Uint32(sd[16:20])
	if daclOffset == 0 || int(daclOffset) >= len(sd) {
		return nil
	}

	dacl := sd[daclOffset:]
	if len(dacl) < 8 {
		return nil
	}

	aclSize := int(binary.LittleEndian.Uint16(dacl[2:4]))
	aceCount := int(binary.LittleEndian.Uint16(dacl[4:6]))
	if aclSize > len(dacl) {
		aclSize = len(dacl)
	}

	var sids []string
	offset := 8 // ACL header size
	for i := 0; i < aceCount; i++ {
		if offset >= aclSize || offset+4 > len(dacl) {
			break
		}

		aceType := dacl[offset]
		aceSize := int(binary.LittleEndian.Uint16(dacl[offset+2 : offset+4]))
		if aceSize == 0 {
			break
		}

		// Only process ACCESS_ALLOWED (0x00) and ACCESS_ALLOWED_OBJECT (0x05)
		if aceType == 0x00 {
			// Standard ACE: header(8) + SID
			if sid := parseSIDFromBuffer(dacl, offset+8); sid != "" {
				sids = append(sids, sid)
			}
		} else if aceType == 0x05 {
			// Object ACE: header(8) + objectFlags(4) + optional GUIDs + SID
			if offset+12 <= len(dacl) {
				objectFlags := binary.LittleEndian.Uint32(dacl[offset+8 : offset+12])
				sidOff := 12
				if objectFlags&0x01 != 0 { // ACE_OBJECT_TYPE_PRESENT
					sidOff += 16
				}
				if objectFlags&0x02 != 0 { // ACE_INHERITED_OBJECT_TYPE_PRESENT
					sidOff += 16
				}
				if sid := parseSIDFromBuffer(dacl, offset+sidOff); sid != "" {
					sids = append(sids, sid)
				}
			}
		}

		offset += aceSize
	}

	return sids
}

// parseSIDFromBuffer parses a Windows SID from binary format to string (S-1-5-21-...).
func parseSIDFromBuffer(buf []byte, offset int) string {
	if offset+8 > len(buf) {
		return ""
	}

	revision := buf[offset]
	subCount := int(buf[offset+1])
	if subCount > 15 || offset+8+subCount*4 > len(buf) {
		return ""
	}

	// 6-byte big-endian identifier authority
	var authority uint64
	for i := 0; i < 6; i++ {
		authority = (authority << 8) | uint64(buf[offset+2+i])
	}

	sid := fmt.Sprintf("S-%d-%d", revision, authority)
	for i := 0; i < subCount; i++ {
		sub := binary.LittleEndian.Uint32(buf[offset+8+i*4 : offset+12+i*4])
		sid += fmt.Sprintf("-%d", sub)
	}

	return sid
}

// IsPrivilegedSID reports whether a SID ends with a well-known privileged group suffix
// (Domain Admins, Enterprise Admins, Schema Admins, Administrators, etc.).
func IsPrivilegedSID(sid string) bool {
	if sid == "" {
		return false
	}
	for suffix := range types.PrivilegedSIDSuffixes {
		if strings.HasSuffix(sid, suffix) {
			return true
		}
	}
	return false
}
