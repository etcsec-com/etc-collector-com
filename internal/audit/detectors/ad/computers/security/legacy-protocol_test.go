package security

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// A prior version of this detector claimed to have detected SMBv1 and NTLMv1 via a
// static `"protocols": []string{"SMBv1","NTLMv1","DES","RC4"}` list, when
// it never observes either protocol. This pins that the misleading
// attribution is gone and Details instead reports which of the two signals
// actually measured (legacy OS, weak Kerberos encryption) fired.
func TestLegacyProtocol_NoFalseProtocolClaim(t *testing.T) {
	c := types.Computer{
		DN:              "CN=OLDBOX,DC=example,DC=com",
		OperatingSystem: "Windows Server 2003",
	}
	data := &audit.DetectorData{IncludeDetails: true, Computers: []types.Computer{c}}

	findings := NewLegacyProtocolDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.Count != 1 {
		t.Fatalf("Count = %d, want 1", f.Count)
	}
	if _, present := f.Details["protocols"]; present {
		t.Fatalf("Details still carries a static \"protocols\" list implying SMBv1/NTLMv1 were observed - they are not measured by this detector")
	}
	if got := f.Details["legacyOSCount"]; got != 1 {
		t.Fatalf("Details[legacyOSCount] = %v, want 1", got)
	}
	if got := f.Details["weakKerberosEncryption"]; got != 0 {
		t.Fatalf("Details[weakKerberosEncryption] = %v, want 0", got)
	}
}

// TestLegacyProtocol covers both branches (end-of-life OS string vs
// msDS-SupportedEncryptionTypes lacking AES) and the disabled-computer
// exclusion. All fixtures use hardcoded literals distinct from the 0x18 mask
// the code checks against, pinned to the real Kerberos etype bits ([MS-KILE]
// 2.2.7: DES_CBC_CRC=0x1, DES_CBC_MD5=0x2, RC4_HMAC_MD5=0x4, AES128=0x8,
// AES256=0x10) - a drift in the mask's numeric value could never make a test
// built from the mask itself fail (the same structural blindness that let
// the LAPS GUID constant stay wrong for months).
func TestLegacyProtocol(t *testing.T) {
	computerDN := "CN=WKS01,OU=Workstations,DC=test,DC=local"

	osCases := []struct {
		name string
		os   string
	}{
		{"Windows XP", "Windows XP Professional"},
		{"Windows 2000", "Windows 2000 Server"},
		{"Windows NT", "Windows NT 4.0"},
		{"Server 2003", "Windows Server 2003 R2"},
		{"Windows Vista", "Windows Vista Business"},
	}
	for _, tc := range osCases {
		t.Run("OS motif "+tc.name+" fires", func(t *testing.T) {
			data := &audit.DetectorData{
				Computers: []types.Computer{
					{DN: computerDN, SAMAccountName: "WKS01$", OperatingSystem: tc.os},
				},
			}
			findings := NewLegacyProtocolDetector().Detect(context.Background(), data)
			if findings[0].Count != 1 {
				t.Fatalf("OS %q must fire, got count=%d", tc.os, findings[0].Count)
			}
		})
	}

	t.Run("literal attribute 4 (RC4 only, no AES) fires", func(t *testing.T) {
		data := &audit.DetectorData{
			Computers: []types.Computer{
				{DN: computerDN, SAMAccountName: "WKS01$", OperatingSystem: "Windows 10 Enterprise", SupportedEncryptionTypes: 4},
			},
		}
		findings := NewLegacyProtocolDetector().Detect(context.Background(), data)
		if findings[0].Count != 1 {
			t.Fatalf("literal 4 (RC4 only, no AES bit) must fire, got count=%d", findings[0].Count)
		}
	})

	// The negative-value trap this ticket exists to close: -2147483644 =
	// 0x80000004 (RC4 bit + sign bit, no AES bit). Under the old `> 0` guard
	// this was a false negative.
	t.Run("literal negative -2147483644 (0x80000004: RC4 and sign bit, no AES) fires", func(t *testing.T) {
		data := &audit.DetectorData{
			Computers: []types.Computer{
				{DN: computerDN, SAMAccountName: "WKS01$", OperatingSystem: "Windows 10 Enterprise", SupportedEncryptionTypes: -2147483644},
			},
		}
		findings := NewLegacyProtocolDetector().Detect(context.Background(), data)
		if findings[0].Count != 1 {
			t.Fatalf("a negative SupportedEncryptionTypes carrying no AES bit must fire, got count=%d", findings[0].Count)
		}
	})

	// 0x20 (bit 5) is AES256-CTS-HMAC-SHA1-96-SK: it only enforces AES
	// session keys on top of whatever ticket encryption type is actually
	// negotiated, it is not itself a ticket encryption type. 36 (0x24) pairs
	// it with RC4 alone (no AES128/AES256 ticket bit), so the 0x18 mask
	// correctly ignores bit 0x20 and this must fire like plain RC4 (4) does.
	t.Run("literal attribute 36 (0x24: RC4+AES256-SK, no ticket AES bit) fires", func(t *testing.T) {
		data := &audit.DetectorData{
			Computers: []types.Computer{
				{DN: computerDN, SAMAccountName: "WKS01$", OperatingSystem: "Windows 10 Enterprise", SupportedEncryptionTypes: 36},
			},
		}
		findings := NewLegacyProtocolDetector().Detect(context.Background(), data)
		if findings[0].Count != 1 {
			t.Fatalf("literal 36 (RC4+AES256-SK, no ticket AES bit) must fire, got count=%d", findings[0].Count)
		}
	})

	t.Run("Windows 10 Enterprise, no weak attribute, does NOT fire", func(t *testing.T) {
		data := &audit.DetectorData{
			Computers: []types.Computer{
				{DN: computerDN, SAMAccountName: "WKS01$", OperatingSystem: "Windows 10 Enterprise"},
			},
		}
		findings := NewLegacyProtocolDetector().Detect(context.Background(), data)
		if findings[0].Count != 0 {
			t.Fatalf("Windows 10 Enterprise must not fire, got count=%d", findings[0].Count)
		}
	})

	// Coverage gap, pinned not corrected (see ticket): the OS motif list does
	// not cover Windows 7, Windows 8, Server 2008(R2) or Server 2012(R2),
	// even though all predate SMBv1 being disabled by default (Windows 10
	// 1709 / Server 2019) - the same justification the Description gives for
	// the 5 motifs that ARE covered. This test pins the current behavior,
	// not the desired one.
	t.Run("Windows Server 2008 R2, coverage gap, does NOT fire", func(t *testing.T) {
		data := &audit.DetectorData{
			Computers: []types.Computer{
				{DN: computerDN, SAMAccountName: "WKS01$", OperatingSystem: "Windows Server 2008 R2 Standard"},
			},
		}
		findings := NewLegacyProtocolDetector().Detect(context.Background(), data)
		if findings[0].Count != 0 {
			t.Fatalf("Windows Server 2008 R2 is not in legacyOSPatterns today, must not fire, got count=%d", findings[0].Count)
		}
	})

	t.Run("Windows 7 Professional, coverage gap, does NOT fire", func(t *testing.T) {
		data := &audit.DetectorData{
			Computers: []types.Computer{
				{DN: computerDN, SAMAccountName: "WKS01$", OperatingSystem: "Windows 7 Professional"},
			},
		}
		findings := NewLegacyProtocolDetector().Detect(context.Background(), data)
		if findings[0].Count != 0 {
			t.Fatalf("Windows 7 is not in legacyOSPatterns today, must not fire, got count=%d", findings[0].Count)
		}
	})

	t.Run("literal attribute 8 (AES128 alone) does NOT fire", func(t *testing.T) {
		data := &audit.DetectorData{
			Computers: []types.Computer{
				{DN: computerDN, SAMAccountName: "WKS01$", OperatingSystem: "Windows 10 Enterprise", SupportedEncryptionTypes: 8},
			},
		}
		findings := NewLegacyProtocolDetector().Detect(context.Background(), data)
		if findings[0].Count != 0 {
			t.Fatalf("literal 8 (AES128 alone) must not fire, got count=%d", findings[0].Count)
		}
	})

	t.Run("literal attribute 16 (AES256 alone) does NOT fire", func(t *testing.T) {
		data := &audit.DetectorData{
			Computers: []types.Computer{
				{DN: computerDN, SAMAccountName: "WKS01$", OperatingSystem: "Windows 10 Enterprise", SupportedEncryptionTypes: 16},
			},
		}
		findings := NewLegacyProtocolDetector().Detect(context.Background(), data)
		if findings[0].Count != 0 {
			t.Fatalf("literal 16 (AES256 alone) must not fire, got count=%d", findings[0].Count)
		}
	})

	t.Run("literal attribute 24 (AES128+AES256, the neutral lab state) does NOT fire", func(t *testing.T) {
		data := &audit.DetectorData{
			Computers: []types.Computer{
				{DN: computerDN, SAMAccountName: "WKS01$", OperatingSystem: "Windows 10 Enterprise", SupportedEncryptionTypes: 24},
			},
		}
		findings := NewLegacyProtocolDetector().Detect(context.Background(), data)
		if findings[0].Count != 0 {
			t.Fatalf("literal 24 (both AES bits present) must not fire, got count=%d", findings[0].Count)
		}
	})

	// The trap: 0 means "attribute never set", not "no AES support". Without
	// the guard, (0 & 0x18) == 0 is trivially true and this would fire for
	// almost every default computer account.
	t.Run("literal attribute 0 (the trap: attribute never set) does NOT fire", func(t *testing.T) {
		data := &audit.DetectorData{
			Computers: []types.Computer{
				{DN: computerDN, SAMAccountName: "WKS01$", OperatingSystem: "Windows 10 Enterprise", SupportedEncryptionTypes: 0},
			},
		}
		findings := NewLegacyProtocolDetector().Detect(context.Background(), data)
		if findings[0].Count != 0 {
			t.Fatalf("literal 0 (attribute never set) must not fire, got count=%d", findings[0].Count)
		}
	})

	// -8 (0xFFFFFFF8) is negative but its low bits carry AES128|AES256 (bits
	// 3-4 survive two's-complement sign extension unchanged): distinguishes
	// "!= 0 catches every negative value" from "!= 0 only removes the
	// zero-guard, the mask still decides".
	t.Run("literal negative -8 (0xFFFFFFF8, AES bits present) does NOT fire", func(t *testing.T) {
		data := &audit.DetectorData{
			Computers: []types.Computer{
				{DN: computerDN, SAMAccountName: "WKS01$", OperatingSystem: "Windows 10 Enterprise", SupportedEncryptionTypes: -8},
			},
		}
		findings := NewLegacyProtocolDetector().Detect(context.Background(), data)
		if findings[0].Count != 0 {
			t.Fatalf("a negative SupportedEncryptionTypes whose low bits carry AES128|AES256 must not fire, got count=%d", findings[0].Count)
		}
	})

	t.Run("disabled computer, Windows XP with attribute 4, does NOT fire", func(t *testing.T) {
		data := &audit.DetectorData{
			Computers: []types.Computer{
				{DN: computerDN, SAMAccountName: "WKS01$", Disabled: true, OperatingSystem: "Windows XP Professional", SupportedEncryptionTypes: 4},
			},
		}
		findings := NewLegacyProtocolDetector().Detect(context.Background(), data)
		if findings[0].Count != 0 {
			t.Fatalf("a disabled computer must be excluded before either branch is evaluated, got count=%d", findings[0].Count)
		}
	})

	t.Run("legacy OS with weak attribute counts once, via legacyOSCount only", func(t *testing.T) {
		data := &audit.DetectorData{
			IncludeDetails: true,
			Computers: []types.Computer{
				{DN: computerDN, SAMAccountName: "WKS01$", OperatingSystem: "Windows XP Professional", SupportedEncryptionTypes: 4},
			},
		}
		findings := NewLegacyProtocolDetector().Detect(context.Background(), data)
		if findings[0].Count != 1 {
			t.Fatalf("one computer matching both branches must count once, got count=%d", findings[0].Count)
		}
		if got := findings[0].Details["legacyOSCount"]; got != 1 {
			t.Fatalf("Details[legacyOSCount] = %v, want 1 (the OS branch's continue must skip the encryption branch)", got)
		}
		if got := findings[0].Details["weakKerberosEncryption"]; got != 0 {
			t.Fatalf("Details[weakKerberosEncryption] = %v, want 0 (the OS branch's continue must skip the encryption branch)", got)
		}
	})
}
