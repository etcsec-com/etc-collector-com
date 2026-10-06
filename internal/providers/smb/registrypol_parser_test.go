package smb

import (
	"encoding/binary"
	"testing"
)

// utf16leZ encodes s as UTF-16LE with a 2-byte null terminator.
func utf16leZ(s string) []byte {
	var b []byte
	for _, r := range s {
		b = append(b, byte(r), byte(r>>8))
	}
	return append(b, 0x00, 0x00)
}

// buildPRegEntry encodes one [key;valueName;type;size;data] Registry.pol entry.
func buildPRegEntry(key, valueName string, typ uint32, data []byte) []byte {
	var b []byte
	b = append(b, 0x5B, 0x00) // '['
	b = append(b, utf16leZ(key)...)
	b = append(b, 0x3B, 0x00) // ';'
	b = append(b, utf16leZ(valueName)...)
	b = append(b, 0x3B, 0x00) // ';'
	typBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(typBuf, typ)
	b = append(b, typBuf...)
	b = append(b, 0x3B, 0x00) // ';'
	sizeBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(sizeBuf, uint32(len(data)))
	b = append(b, sizeBuf...)
	b = append(b, 0x3B, 0x00) // ';'
	b = append(b, data...)
	b = append(b, 0x5D, 0x00) // ']'
	return b
}

// buildPReg wraps entries with the "PReg" header (magic + version).
func buildPReg(entries ...[]byte) []byte {
	b := append([]byte("PReg"), 0x01, 0x00, 0x00, 0x00)
	for _, e := range entries {
		b = append(b, e...)
	}
	return b
}

func dword(v uint32) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, v)
	return b
}

// TestParseRegistryPol_CredentialGuardLsaCfgFlags_DeviceGuardKey is the
// BP039_CRED_GUARD_LIMITED_SCOPE regression test. The real
// GPO-deployed Credential Guard setting lives at
// SOFTWARE\Policies\Microsoft\Windows\DeviceGuard\LsaCfgFlags - the key
// path contains "deviceguard", not "lsa". The old switch case required
// "lsa" in keyLower, so this entry (the only shape Windows ever writes) was
// silently dropped and rs.LsaCfgFlags stayed nil forever, leaving
// BP039_CRED_GUARD_LIMITED_SCOPE permanently blind (maxCG always -1).
func TestParseRegistryPol_CredentialGuardLsaCfgFlags_DeviceGuardKey(t *testing.T) {
	entry := buildPRegEntry(
		`SOFTWARE\Policies\Microsoft\Windows\DeviceGuard`,
		"LsaCfgFlags",
		4, // REG_DWORD
		dword(1),
	)
	data := buildPReg(entry)

	rs := ParseRegistryPol(data)

	if rs == nil {
		t.Fatal("ParseRegistryPol returned nil for a DeviceGuard\\LsaCfgFlags entry")
	}
	if rs.LsaCfgFlags == nil {
		t.Fatal("LsaCfgFlags not populated for the real DeviceGuard GPO key (registrypol_parser.go only matched a \"lsa\"-in-path key that Windows never writes)")
	}
	if *rs.LsaCfgFlags != 1 {
		t.Fatalf("LsaCfgFlags = %d, want 1", *rs.LsaCfgFlags)
	}
}

// TestParseRegistryPol_CredentialGuardLsaCfgFlags_LsaKeyStillWorks guards
// against a regression on the pre-existing (synthetic but harmless) "lsa"
// path match while broadening the condition to also accept "deviceguard".
func TestParseRegistryPol_CredentialGuardLsaCfgFlags_LsaKeyStillWorks(t *testing.T) {
	entry := buildPRegEntry(
		`System\CurrentControlSet\Control\Lsa`,
		"LsaCfgFlags",
		4,
		dword(2),
	)
	data := buildPReg(entry)

	rs := ParseRegistryPol(data)

	if rs == nil || rs.LsaCfgFlags == nil {
		t.Fatal("LsaCfgFlags not populated for a Lsa-path key")
	}
	if *rs.LsaCfgFlags != 2 {
		t.Fatalf("LsaCfgFlags = %d, want 2", *rs.LsaCfgFlags)
	}
}

// TestParseRegistryPol_CredentialGuardLsaCfgFlags_LsassExcluded guards the
// pre-existing lsass exclusion: Lsass is a different subsystem and must not
// be mistaken for the Lsa\ policy path.
func TestParseRegistryPol_CredentialGuardLsaCfgFlags_LsassExcluded(t *testing.T) {
	entry := buildPRegEntry(
		`System\CurrentControlSet\Control\Lsa\Lsass`,
		"LsaCfgFlags",
		4,
		dword(1),
	)
	data := buildPReg(entry)

	rs := ParseRegistryPol(data)

	if rs != nil && rs.LsaCfgFlags != nil {
		t.Fatalf("LsaCfgFlags should not be populated from an Lsass-path key, got %d", *rs.LsaCfgFlags)
	}
}

// TestParseRegistryPol_KerberosArmoringDC_EnableCbacAndArmor covers
// KERBEROS_ARMORING_DC_DISABLED (false positive, allume_a_tort=true): the real
// GPO-deployed "KDC support for claims, compound authentication and
// Kerberos armoring" policy writes the value name EnableCbacAndArmor under
// a Kdc\Parameters-shaped key - the old switch case matched
// SupportedEncTypes/SupportedEncryptionTypes instead, a combination no
// real GPO ever writes, so RegistrySettings.KerberosArmoringDC stayed nil
// on every domain (even a correctly configured one), and the detector
// reported Count=1 unconditionally.
func TestParseRegistryPol_KerberosArmoringDC_EnableCbacAndArmor(t *testing.T) {
	entry := buildPRegEntry(
		`System\CurrentControlSet\Services\Kdc\Parameters`,
		"EnableCbacAndArmor",
		4, // REG_DWORD
		dword(2),
	)
	data := buildPReg(entry)

	rs := ParseRegistryPol(data)

	if rs == nil || rs.KerberosArmoringDC == nil {
		t.Fatal("KerberosArmoringDC not populated for the real EnableCbacAndArmor GPO key")
	}
	if *rs.KerberosArmoringDC != 2 {
		t.Fatalf("KerberosArmoringDC = %d, want 2", *rs.KerberosArmoringDC)
	}
}
