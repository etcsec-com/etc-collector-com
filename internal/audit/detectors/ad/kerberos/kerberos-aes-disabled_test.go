package kerberos

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// TestKerberosAesDisabled covers both branches (attribute AES-bits-absent vs
// UAC USE_DES_KEY_ONLY) and the disabled-account exclusion. All fixtures use
// hardcoded literals distinct from the aesSupport/uacUseDESKeyOnly constants
// the code checks against, pinned to the real Kerberos etype bits ([MS-KILE]
// 2.2.7: DES_CBC_CRC=0x1, DES_CBC_MD5=0x2, RC4_HMAC_MD5=0x4, AES128=0x8,
// AES256=0x10) and the real UAC bit layout - a drift in either constant's
// numeric value could never make a test built from the constants themselves
// fail (the same structural blindness that let the LAPS GUID constant stay
// wrong for months).
func TestKerberosAesDisabled(t *testing.T) {
	userDN := "CN=svc,OU=Services,DC=test,DC=local"

	t.Run("literal attribute 4 (RC4 only, no AES) fires", func(t *testing.T) {
		data := &audit.DetectorData{
			Users: []types.User{
				{DN: userDN, SAMAccountName: "svc", SupportedEncryptionTypes: 4},
			},
			IncludeDetails: true,
		}
		findings := NewKerberosAesDisabledDetector().Detect(context.Background(), data)
		if len(findings) != 1 || findings[0].Count != 1 {
			t.Fatalf("literal 4 (RC4 only, no AES bit) must fire, got %+v", findings)
		}
		if findings[0].Severity != types.SeverityHigh {
			t.Fatalf("severity must stay High, got %s", findings[0].Severity)
		}
	})

	t.Run("literal attribute 3 (DES bits, no AES) fires", func(t *testing.T) {
		data := &audit.DetectorData{
			Users: []types.User{
				{DN: userDN, SAMAccountName: "svc", SupportedEncryptionTypes: 3},
			},
		}
		findings := NewKerberosAesDisabledDetector().Detect(context.Background(), data)
		if findings[0].Count != 1 {
			t.Fatalf("literal 3 (DES bits, no AES bit) must fire, got count=%d", findings[0].Count)
		}
	})

	t.Run("UAC bit 0x200000 with AES-carrying attribute (24) fires via UAC branch alone", func(t *testing.T) {
		data := &audit.DetectorData{
			Users: []types.User{
				{DN: userDN, SAMAccountName: "svc", UserAccountControl: 0x200000, SupportedEncryptionTypes: 24},
			},
		}
		findings := NewKerberosAesDisabledDetector().Detect(context.Background(), data)
		if findings[0].Count != 1 {
			t.Fatalf("UAC bit 0x200000 must fire even though the attribute (24) carries both AES bits, got count=%d", findings[0].Count)
		}
	})

	t.Run("literal negative -2147483644 (0x80000004: RC4 and sign bit, no AES) fires", func(t *testing.T) {
		data := &audit.DetectorData{
			Users: []types.User{
				{DN: userDN, SAMAccountName: "svc", SupportedEncryptionTypes: -2147483644},
			},
		}
		findings := NewKerberosAesDisabledDetector().Detect(context.Background(), data)
		if findings[0].Count != 1 {
			t.Fatalf("a negative SupportedEncryptionTypes carrying no AES bit must fire, got count=%d", findings[0].Count)
		}
	})

	// 0x20 (bit 5) is AES256-CTS-HMAC-SHA1-96-SK: it only enforces AES
	// session keys on top of whatever ticket encryption type is actually
	// negotiated, it is not itself a ticket encryption type. 36 (0x24) pairs
	// it with RC4 alone (no AES128/AES256 ticket bit), so the attribute
	// carries no bit inside aesSupport and this must fire exactly like plain
	// RC4-only (4) does.
	t.Run("literal attribute 36 (0x24: RC4+AES256-SK, no ticket AES bit) fires", func(t *testing.T) {
		data := &audit.DetectorData{
			Users: []types.User{
				{DN: userDN, SAMAccountName: "svc", SupportedEncryptionTypes: 36},
			},
		}
		findings := NewKerberosAesDisabledDetector().Detect(context.Background(), data)
		if findings[0].Count != 1 {
			t.Fatalf("literal 36 (RC4+AES256-SK, no ticket AES bit) must fire, got count=%d", findings[0].Count)
		}
	})

	t.Run("literal attribute 24 (AES128+AES256, the neutral lab state) does NOT fire", func(t *testing.T) {
		data := &audit.DetectorData{
			Users: []types.User{
				{DN: userDN, SAMAccountName: "svc", SupportedEncryptionTypes: 24},
			},
		}
		findings := NewKerberosAesDisabledDetector().Detect(context.Background(), data)
		if findings[0].Count != 0 {
			t.Fatalf("literal 24 (both AES bits present) must not fire, got count=%d", findings[0].Count)
		}
	})

	t.Run("literal attribute 8 (AES128 alone) does NOT fire", func(t *testing.T) {
		data := &audit.DetectorData{
			Users: []types.User{
				{DN: userDN, SAMAccountName: "svc", SupportedEncryptionTypes: 8},
			},
		}
		findings := NewKerberosAesDisabledDetector().Detect(context.Background(), data)
		if findings[0].Count != 0 {
			t.Fatalf("literal 8 (AES128 alone) must not fire, got count=%d", findings[0].Count)
		}
	})

	t.Run("literal attribute 16 (AES256 alone) does NOT fire", func(t *testing.T) {
		data := &audit.DetectorData{
			Users: []types.User{
				{DN: userDN, SAMAccountName: "svc", SupportedEncryptionTypes: 16},
			},
		}
		findings := NewKerberosAesDisabledDetector().Detect(context.Background(), data)
		if findings[0].Count != 0 {
			t.Fatalf("literal 16 (AES256 alone) must not fire, got count=%d", findings[0].Count)
		}
	})

	// The trap this ticket exists to avoid: 0 means "attribute never set",
	// not "no AES support". Without the guard, (0 & aesSupport) == 0 is
	// trivially true and this would fire for almost every default account.
	t.Run("literal attribute 0 (the trap: attribute never set) does NOT fire", func(t *testing.T) {
		data := &audit.DetectorData{
			Users: []types.User{
				{DN: userDN, SAMAccountName: "svc", SupportedEncryptionTypes: 0},
			},
		}
		findings := NewKerberosAesDisabledDetector().Detect(context.Background(), data)
		if findings[0].Count != 0 {
			t.Fatalf("literal 0 (attribute never set) must not fire, got count=%d", findings[0].Count)
		}
	})

	// -8 (0xFFFFFFF8) is negative but its low bits carry AES128|AES256
	// (bits 3-4 survive two's-complement sign extension unchanged, same
	// argument as WeakEncryptionDESDetector's negative-value fix):
	// distinguishes "!= 0 catches every negative value" from "!= 0 only
	// removes the zero-guard, the mask still decides".
	t.Run("literal negative -8 (0xFFFFFFF8, AES bits present) does NOT fire", func(t *testing.T) {
		data := &audit.DetectorData{
			Users: []types.User{
				{DN: userDN, SAMAccountName: "svc", SupportedEncryptionTypes: -8},
			},
		}
		findings := NewKerberosAesDisabledDetector().Detect(context.Background(), data)
		if findings[0].Count != 0 {
			t.Fatalf("a negative SupportedEncryptionTypes whose low bits carry AES128|AES256 must not fire, got count=%d", findings[0].Count)
		}
	})

	t.Run("literal UAC bit 0x100000 (adjacent NOT_DELEGATED, not DES-only) does NOT fire", func(t *testing.T) {
		data := &audit.DetectorData{
			Users: []types.User{
				{DN: userDN, SAMAccountName: "svc", UserAccountControl: 0x100000},
			},
		}
		findings := NewKerberosAesDisabledDetector().Detect(context.Background(), data)
		if findings[0].Count != 0 {
			t.Fatalf("an adjacent UAC bit (0x100000, not USE_DES_KEY_ONLY) must not fire, got count=%d", findings[0].Count)
		}
	})

	t.Run("disabled account, attribute 4 (RC4 only), does NOT fire", func(t *testing.T) {
		data := &audit.DetectorData{
			Users: []types.User{
				{DN: userDN, SAMAccountName: "svc", Disabled: true, SupportedEncryptionTypes: 4},
			},
		}
		findings := NewKerberosAesDisabledDetector().Detect(context.Background(), data)
		if findings[0].Count != 0 {
			t.Fatalf("a disabled account must be excluded before either branch is evaluated, got count=%d", findings[0].Count)
		}
	})

	t.Run("both branches set counts once, not twice", func(t *testing.T) {
		data := &audit.DetectorData{
			Users: []types.User{
				{DN: userDN, SAMAccountName: "svc", UserAccountControl: 0x200000, SupportedEncryptionTypes: 4},
			},
		}
		findings := NewKerberosAesDisabledDetector().Detect(context.Background(), data)
		if findings[0].Count != 1 {
			t.Fatalf("one account matching both branches must count once, got count=%d", findings[0].Count)
		}
	})
}
