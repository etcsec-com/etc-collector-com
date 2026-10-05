package kerberos

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// TestWeakEncryptionRC4 covers the AND-NOT condition (RC4 bit present, no AES
// bit present) and pins the fact that this detector applies no Disabled
// filter at all, unlike its two siblings in this package. All fixtures use
// hardcoded literals distinct from the 0x4/0x18 masks the code checks
// against, pinned to the real Kerberos etype bits ([MS-KILE] 2.2.7:
// DES_CBC_CRC=0x1, DES_CBC_MD5=0x2, RC4_HMAC_MD5=0x4, AES128=0x8,
// AES256=0x10) - a drift in the code's own literal masks could never make a
// test built from those same literals fail (the same structural blindness
// that let the LAPS GUID constant stay wrong for months).
func TestWeakEncryptionRC4(t *testing.T) {
	userDN := "CN=svc,OU=Services,DC=test,DC=local"

	t.Run("literal attribute 4 (RC4 alone) fires", func(t *testing.T) {
		data := &audit.DetectorData{
			Users: []types.User{
				{DN: userDN, SAMAccountName: "svc", SupportedEncryptionTypes: 4},
			},
			IncludeDetails: true,
		}
		findings := NewWeakEncryptionRC4Detector().Detect(context.Background(), data)
		if len(findings) != 1 || findings[0].Count != 1 {
			t.Fatalf("literal 4 (RC4 alone) must fire, got %+v", findings)
		}
		if findings[0].Type != "WEAK_ENCRYPTION_RC4" {
			t.Fatalf("finding type must stay WEAK_ENCRYPTION_RC4, got %s", findings[0].Type)
		}
		if findings[0].Severity != types.SeverityMedium {
			t.Fatalf("severity must stay Medium, got %s", findings[0].Severity)
		}
	})

	t.Run("literal attribute 5 (DES_CBC_CRC+RC4) fires", func(t *testing.T) {
		data := &audit.DetectorData{
			Users: []types.User{
				{DN: userDN, SAMAccountName: "svc", SupportedEncryptionTypes: 5},
			},
		}
		findings := NewWeakEncryptionRC4Detector().Detect(context.Background(), data)
		if findings[0].Count != 1 {
			t.Fatalf("literal 5 (DES_CBC_CRC+RC4) must fire, got count=%d", findings[0].Count)
		}
	})

	t.Run("literal attribute 6 (DES_CBC_MD5+RC4) fires", func(t *testing.T) {
		data := &audit.DetectorData{
			Users: []types.User{
				{DN: userDN, SAMAccountName: "svc", SupportedEncryptionTypes: 6},
			},
		}
		findings := NewWeakEncryptionRC4Detector().Detect(context.Background(), data)
		if findings[0].Count != 1 {
			t.Fatalf("literal 6 (DES_CBC_MD5+RC4) must fire, got count=%d", findings[0].Count)
		}
	})

	t.Run("literal attribute 7 (both DES bits+RC4) fires", func(t *testing.T) {
		data := &audit.DetectorData{
			Users: []types.User{
				{DN: userDN, SAMAccountName: "svc", SupportedEncryptionTypes: 7},
			},
		}
		findings := NewWeakEncryptionRC4Detector().Detect(context.Background(), data)
		if findings[0].Count != 1 {
			t.Fatalf("literal 7 (DES+DES+RC4) must fire, got count=%d", findings[0].Count)
		}
	})

	// 0x80000004: sign bit plus RC4, no AES bit. A bitwise AND on a signed
	// int operates on its two's-complement bits unchanged, so this must fire
	// exactly like the positive value 4 does.
	t.Run("literal negative -2147483644 (0x80000004: sign bit+RC4, no AES) fires", func(t *testing.T) {
		data := &audit.DetectorData{
			Users: []types.User{
				{DN: userDN, SAMAccountName: "svc", SupportedEncryptionTypes: -2147483644},
			},
		}
		findings := NewWeakEncryptionRC4Detector().Detect(context.Background(), data)
		if findings[0].Count != 1 {
			t.Fatalf("a negative SupportedEncryptionTypes carrying RC4 without AES must fire, got count=%d", findings[0].Count)
		}
	})

	// This detector applies no Disabled filter anywhere in its condition -
	// unlike KERBEROS_AES_DISABLED and KERBEROS_RC4_FALLBACK in this same
	// package, both of which skip Disabled accounts before evaluating either
	// of their branches. This case pins that current, unfiltered behavior.
	t.Run("disabled account, attribute 4 (RC4 alone), still fires", func(t *testing.T) {
		data := &audit.DetectorData{
			Users: []types.User{
				{DN: userDN, SAMAccountName: "svc", Disabled: true, SupportedEncryptionTypes: 4},
			},
		}
		findings := NewWeakEncryptionRC4Detector().Detect(context.Background(), data)
		if findings[0].Count != 1 {
			t.Fatalf("a disabled account with RC4 and no AES must still fire (no Disabled filter exists), got count=%d", findings[0].Count)
		}
	})

	// 0x20 (bit 5) is AES256-CTS-HMAC-SHA1-96-SK: it only enforces AES session
	// keys on top of whatever ticket encryption type is actually negotiated,
	// it is not itself a ticket encryption type. A real, documented
	// configuration pairs it with RC4 (0x24) to keep RC4 tickets while still
	// requiring an AES-protected session key - the account's tickets remain
	// RC4-encrypted, so this must fire exactly like plain RC4 (4) does. The
	// 0x18 mask correctly ignores bit 0x20 here, since it is not a ticket AES
	// bit.
	t.Run("literal attribute 36 (0x24: RC4+AES256-SK, no ticket AES bit) fires", func(t *testing.T) {
		data := &audit.DetectorData{
			Users: []types.User{
				{DN: userDN, SAMAccountName: "svc", SupportedEncryptionTypes: 36},
			},
		}
		findings := NewWeakEncryptionRC4Detector().Detect(context.Background(), data)
		if findings[0].Count != 1 {
			t.Fatalf("literal 36 (RC4+AES256-SK, no ticket AES bit) must fire, got count=%d", findings[0].Count)
		}
	})

	// 0 means "attribute never set", not "no bits present". 0 masked with
	// any nonzero bit is always 0, so hasRc4 is false regardless of whether
	// the zero-guard exists. This case pins the observable non-firing
	// behavior for that value.
	t.Run("literal attribute 0 (the trap: attribute never set) does NOT fire", func(t *testing.T) {
		data := &audit.DetectorData{
			Users: []types.User{
				{DN: userDN, SAMAccountName: "svc", SupportedEncryptionTypes: 0},
			},
		}
		findings := NewWeakEncryptionRC4Detector().Detect(context.Background(), data)
		if findings[0].Count != 0 {
			t.Fatalf("literal 0 (attribute never set) must not fire, got count=%d", findings[0].Count)
		}
	})

	t.Run("literal attribute 3 (DES bits only, no RC4) does NOT fire", func(t *testing.T) {
		data := &audit.DetectorData{
			Users: []types.User{
				{DN: userDN, SAMAccountName: "svc", SupportedEncryptionTypes: 3},
			},
		}
		findings := NewWeakEncryptionRC4Detector().Detect(context.Background(), data)
		if findings[0].Count != 0 {
			t.Fatalf("literal 3 (DES bits only) must not fire, got count=%d", findings[0].Count)
		}
	})

	t.Run("literal attribute 12 (RC4+AES128) does NOT fire", func(t *testing.T) {
		data := &audit.DetectorData{
			Users: []types.User{
				{DN: userDN, SAMAccountName: "svc", SupportedEncryptionTypes: 12},
			},
		}
		findings := NewWeakEncryptionRC4Detector().Detect(context.Background(), data)
		if findings[0].Count != 0 {
			t.Fatalf("literal 12 (RC4+AES128) must not fire, got count=%d", findings[0].Count)
		}
	})

	t.Run("literal attribute 20 (RC4+AES256) does NOT fire", func(t *testing.T) {
		data := &audit.DetectorData{
			Users: []types.User{
				{DN: userDN, SAMAccountName: "svc", SupportedEncryptionTypes: 20},
			},
		}
		findings := NewWeakEncryptionRC4Detector().Detect(context.Background(), data)
		if findings[0].Count != 0 {
			t.Fatalf("literal 20 (RC4+AES256) must not fire, got count=%d", findings[0].Count)
		}
	})

	t.Run("literal attribute 24 (both AES bits, no RC4) does NOT fire", func(t *testing.T) {
		data := &audit.DetectorData{
			Users: []types.User{
				{DN: userDN, SAMAccountName: "svc", SupportedEncryptionTypes: 24},
			},
		}
		findings := NewWeakEncryptionRC4Detector().Detect(context.Background(), data)
		if findings[0].Count != 0 {
			t.Fatalf("literal 24 (both AES bits, no RC4) must not fire, got count=%d", findings[0].Count)
		}
	})

	t.Run("literal attribute 28 (RC4+AES128+AES256) does NOT fire", func(t *testing.T) {
		data := &audit.DetectorData{
			Users: []types.User{
				{DN: userDN, SAMAccountName: "svc", SupportedEncryptionTypes: 28},
			},
		}
		findings := NewWeakEncryptionRC4Detector().Detect(context.Background(), data)
		if findings[0].Count != 0 {
			t.Fatalf("literal 28 (RC4+AES128+AES256) must not fire, got count=%d", findings[0].Count)
		}
	})

	t.Run("literal negative -1 (every bit set, so AES is present) does NOT fire", func(t *testing.T) {
		data := &audit.DetectorData{
			Users: []types.User{
				{DN: userDN, SAMAccountName: "svc", SupportedEncryptionTypes: -1},
			},
		}
		findings := NewWeakEncryptionRC4Detector().Detect(context.Background(), data)
		if findings[0].Count != 0 {
			t.Fatalf("literal -1 (every bit set) must not fire, got count=%d", findings[0].Count)
		}
	})
}
