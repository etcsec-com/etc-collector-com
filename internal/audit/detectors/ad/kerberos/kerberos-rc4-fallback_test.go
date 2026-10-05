package kerberos

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// TestKerberosRc4Fallback covers the AND condition (both an AES bit and the
// RC4 bit must be present), the behavior for a zero attribute, and the
// disabled-account exclusion. All fixtures use hardcoded literals distinct from the
// aesSupport/rc4Support constants the code checks against, pinned to the
// real Kerberos etype bits ([MS-KILE] 2.2.7: DES_CBC_CRC=0x1, DES_CBC_MD5=0x2,
// RC4_HMAC_MD5=0x4, AES128=0x8, AES256=0x10) - a drift in either constant's
// numeric value could never make a test built from the constants themselves
// fail (the same structural blindness that let the LAPS GUID constant stay
// wrong for months).
func TestKerberosRc4Fallback(t *testing.T) {
	userDN := "CN=svc,OU=Services,DC=test,DC=local"

	t.Run("literal attribute 28 (RC4+AES128+AES256) fires", func(t *testing.T) {
		data := &audit.DetectorData{
			Users: []types.User{
				{DN: userDN, SAMAccountName: "svc", SupportedEncryptionTypes: 28},
			},
			IncludeDetails: true,
		}
		findings := NewKerberosRc4FallbackDetector().Detect(context.Background(), data)
		if len(findings) != 1 || findings[0].Count != 1 {
			t.Fatalf("literal 28 (RC4+AES128+AES256) must fire, got %+v", findings)
		}
		if findings[0].Severity != types.SeverityMedium {
			t.Fatalf("severity must stay Medium, got %s", findings[0].Severity)
		}
	})

	t.Run("literal attribute 12 (RC4+AES128, no AES256) fires", func(t *testing.T) {
		data := &audit.DetectorData{
			Users: []types.User{
				{DN: userDN, SAMAccountName: "svc", SupportedEncryptionTypes: 12},
			},
		}
		findings := NewKerberosRc4FallbackDetector().Detect(context.Background(), data)
		if findings[0].Count != 1 {
			t.Fatalf("literal 12 (RC4+AES128) must fire, got count=%d", findings[0].Count)
		}
	})

	t.Run("literal attribute 20 (RC4+AES256, no AES128) fires", func(t *testing.T) {
		data := &audit.DetectorData{
			Users: []types.User{
				{DN: userDN, SAMAccountName: "svc", SupportedEncryptionTypes: 20},
			},
		}
		findings := NewKerberosRc4FallbackDetector().Detect(context.Background(), data)
		if findings[0].Count != 1 {
			t.Fatalf("literal 20 (RC4+AES256) must fire, got count=%d", findings[0].Count)
		}
	})

	t.Run("literal negative -1 (all bits set) fires", func(t *testing.T) {
		data := &audit.DetectorData{
			Users: []types.User{
				{DN: userDN, SAMAccountName: "svc", SupportedEncryptionTypes: -1},
			},
		}
		findings := NewKerberosRc4FallbackDetector().Detect(context.Background(), data)
		if findings[0].Count != 1 {
			t.Fatalf("a negative SupportedEncryptionTypes with every bit set must fire, got count=%d", findings[0].Count)
		}
	})

	// 0 means "attribute never set", not "no bits present". For this
	// detector's AND condition, 0 can never fire regardless of whether the
	// zero-guard exists: 0 masked with any nonzero bit is always 0, so both
	// hasAes and hasRc4 are false either way. This case pins the observable
	// non-firing behavior for that value.
	t.Run("literal attribute 0 (the trap: attribute never set) does NOT fire", func(t *testing.T) {
		data := &audit.DetectorData{
			Users: []types.User{
				{DN: userDN, SAMAccountName: "svc", SupportedEncryptionTypes: 0},
			},
		}
		findings := NewKerberosRc4FallbackDetector().Detect(context.Background(), data)
		if findings[0].Count != 0 {
			t.Fatalf("literal 0 (attribute never set) must not fire, got count=%d", findings[0].Count)
		}
	})

	t.Run("literal attribute 4 (RC4 only, no AES) does NOT fire", func(t *testing.T) {
		data := &audit.DetectorData{
			Users: []types.User{
				{DN: userDN, SAMAccountName: "svc", SupportedEncryptionTypes: 4},
			},
		}
		findings := NewKerberosRc4FallbackDetector().Detect(context.Background(), data)
		if findings[0].Count != 0 {
			t.Fatalf("literal 4 (RC4 only, no AES bit) must not fire, got count=%d", findings[0].Count)
		}
	})

	// 0x20 (bit 5) is AES256-CTS-HMAC-SHA1-96-SK: it only enforces AES
	// session keys on top of whatever ticket encryption type is actually
	// negotiated, it is not itself a ticket encryption type. 36 (0x24) pairs
	// it with RC4 alone (no AES128/AES256 ticket bit), so hasAes stays false
	// and the AND condition cannot fire even though bit 0x20 is present.
	t.Run("literal attribute 36 (0x24: RC4+AES256-SK, no ticket AES bit) does NOT fire", func(t *testing.T) {
		data := &audit.DetectorData{
			Users: []types.User{
				{DN: userDN, SAMAccountName: "svc", SupportedEncryptionTypes: 36},
			},
		}
		findings := NewKerberosRc4FallbackDetector().Detect(context.Background(), data)
		if findings[0].Count != 0 {
			t.Fatalf("literal 36 (RC4+AES256-SK, no ticket AES bit) must not fire, got count=%d", findings[0].Count)
		}
	})

	t.Run("literal attribute 60 (0x3C: RC4+AES128+AES256+AES256-SK) fires", func(t *testing.T) {
		data := &audit.DetectorData{
			Users: []types.User{
				{DN: userDN, SAMAccountName: "svc", SupportedEncryptionTypes: 60},
			},
		}
		findings := NewKerberosRc4FallbackDetector().Detect(context.Background(), data)
		if findings[0].Count != 1 {
			t.Fatalf("literal 60 (RC4+AES128+AES256+AES256-SK) must fire, got count=%d", findings[0].Count)
		}
	})

	t.Run("literal attribute 24 (AES128+AES256, no RC4) does NOT fire", func(t *testing.T) {
		data := &audit.DetectorData{
			Users: []types.User{
				{DN: userDN, SAMAccountName: "svc", SupportedEncryptionTypes: 24},
			},
		}
		findings := NewKerberosRc4FallbackDetector().Detect(context.Background(), data)
		if findings[0].Count != 0 {
			t.Fatalf("literal 24 (both AES bits, no RC4) must not fire, got count=%d", findings[0].Count)
		}
	})

	t.Run("literal attribute 3 (DES bits only) does NOT fire", func(t *testing.T) {
		data := &audit.DetectorData{
			Users: []types.User{
				{DN: userDN, SAMAccountName: "svc", SupportedEncryptionTypes: 3},
			},
		}
		findings := NewKerberosRc4FallbackDetector().Detect(context.Background(), data)
		if findings[0].Count != 0 {
			t.Fatalf("literal 3 (DES bits only) must not fire, got count=%d", findings[0].Count)
		}
	})

	t.Run("literal attribute 7 (DES+RC4, no AES) does NOT fire", func(t *testing.T) {
		data := &audit.DetectorData{
			Users: []types.User{
				{DN: userDN, SAMAccountName: "svc", SupportedEncryptionTypes: 7},
			},
		}
		findings := NewKerberosRc4FallbackDetector().Detect(context.Background(), data)
		if findings[0].Count != 0 {
			t.Fatalf("literal 7 (DES+RC4, no AES bit) must not fire, got count=%d", findings[0].Count)
		}
	})

	t.Run("disabled account, attribute 28 (RC4+AES128+AES256), does NOT fire", func(t *testing.T) {
		data := &audit.DetectorData{
			Users: []types.User{
				{DN: userDN, SAMAccountName: "svc", Disabled: true, SupportedEncryptionTypes: 28},
			},
		}
		findings := NewKerberosRc4FallbackDetector().Detect(context.Background(), data)
		if findings[0].Count != 0 {
			t.Fatalf("a disabled account must be excluded even with both AES and RC4 bits present, got count=%d", findings[0].Count)
		}
	})
}
