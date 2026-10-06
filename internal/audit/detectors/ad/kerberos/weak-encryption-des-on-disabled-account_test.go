package kerberos

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

func TestWeakEncryptionDESOnDisabledAccount(t *testing.T) {
	userDN := "CN=svc,OU=Services,DC=test,DC=local"

	t.Run("disabled + UAC bit branch fires here", func(t *testing.T) {
		data := &audit.DetectorData{
			Users: []types.User{
				{DN: userDN, SAMAccountName: "svc", Disabled: true, UserAccountControl: uacUseDESKeyOnly},
			},
			IncludeDetails: true,
		}
		findings := NewWeakEncryptionDESOnDisabledAccountDetector().Detect(context.Background(), data)
		if len(findings) != 1 || findings[0].Count != 1 {
			t.Fatalf("disabled account with the bit branch must fire here, got %+v", findings)
		}
		if findings[0].Severity != types.SeverityLow {
			t.Fatalf("disabled half must be Low, got %s", findings[0].Severity)
		}
	})

	t.Run("disabled + attribute branch fires here", func(t *testing.T) {
		data := &audit.DetectorData{
			Users: []types.User{
				{DN: userDN, SAMAccountName: "svc", Disabled: true, SupportedEncryptionTypes: desTypes},
			},
			IncludeDetails: true,
		}
		findings := NewWeakEncryptionDESOnDisabledAccountDetector().Detect(context.Background(), data)
		if len(findings) != 1 || findings[0].Count != 1 {
			t.Fatalf("disabled account with the attribute branch must fire here, got %+v", findings)
		}
	})

	// Literal-value cases: the two subtests above build their fixture from
	// the very same uacUseDESKeyOnly/desTypes constants the code checks
	// against, so a drift in either constant's numeric value could never
	// make them fail. These use hardcoded literals distinct from the
	// constants, pinned to the real Kerberos etype bits ([MS-KILE] 2.2.7:
	// DES_CBC_CRC=0x1, DES_CBC_MD5=0x2, RC4_HMAC_MD5=0x4) and the real UAC
	// bit layout.
	t.Run("disabled + literal UAC bit 0x200000 fires here", func(t *testing.T) {
		data := &audit.DetectorData{
			Users: []types.User{
				{DN: userDN, SAMAccountName: "svc", Disabled: true, UserAccountControl: 0x200000},
			},
		}
		findings := NewWeakEncryptionDESOnDisabledAccountDetector().Detect(context.Background(), data)
		if findings[0].Count != 1 {
			t.Fatalf("literal 0x200000 (USE_DES_KEY_ONLY) on a disabled account must fire here, got count=%d", findings[0].Count)
		}
	})

	t.Run("disabled + literal UAC bit 0x100000 (adjacent NOT_DELEGATED, not DES) does NOT fire", func(t *testing.T) {
		data := &audit.DetectorData{
			Users: []types.User{
				{DN: userDN, SAMAccountName: "svc", Disabled: true, UserAccountControl: 0x100000},
			},
		}
		findings := NewWeakEncryptionDESOnDisabledAccountDetector().Detect(context.Background(), data)
		if findings[0].Count != 0 {
			t.Fatalf("an adjacent UAC bit (0x100000, not USE_DES_KEY_ONLY) must not fire, got count=%d", findings[0].Count)
		}
	})

	t.Run("disabled + literal attribute bit 0x1 (DES_CBC_CRC alone) fires here", func(t *testing.T) {
		data := &audit.DetectorData{
			Users: []types.User{
				{DN: userDN, SAMAccountName: "svc", Disabled: true, SupportedEncryptionTypes: 0x1},
			},
		}
		findings := NewWeakEncryptionDESOnDisabledAccountDetector().Detect(context.Background(), data)
		if findings[0].Count != 1 {
			t.Fatalf("literal 0x1 (DES_CBC_CRC alone) on a disabled account must fire here, got count=%d", findings[0].Count)
		}
	})

	t.Run("disabled + literal attribute bit 0x2 (DES_CBC_MD5 alone) fires here", func(t *testing.T) {
		data := &audit.DetectorData{
			Users: []types.User{
				{DN: userDN, SAMAccountName: "svc", Disabled: true, SupportedEncryptionTypes: 0x2},
			},
		}
		findings := NewWeakEncryptionDESOnDisabledAccountDetector().Detect(context.Background(), data)
		if findings[0].Count != 1 {
			t.Fatalf("literal 0x2 (DES_CBC_MD5 alone) on a disabled account must fire here, got count=%d", findings[0].Count)
		}
	})

	t.Run("disabled + literal attribute bit 0x4 (RC4 alone, no DES bit) does NOT fire", func(t *testing.T) {
		data := &audit.DetectorData{
			Users: []types.User{
				{DN: userDN, SAMAccountName: "svc", Disabled: true, SupportedEncryptionTypes: 0x4},
			},
		}
		findings := NewWeakEncryptionDESOnDisabledAccountDetector().Detect(context.Background(), data)
		if findings[0].Count != 0 {
			t.Fatalf("literal 0x4 (RC4 alone, no DES bit) must not fire, got count=%d", findings[0].Count)
		}
	})

	t.Run("active account does NOT fire here, either branch", func(t *testing.T) {
		data := &audit.DetectorData{
			Users: []types.User{
				{DN: userDN, SAMAccountName: "svc-bit", UserAccountControl: uacUseDESKeyOnly},
				{DN: userDN, SAMAccountName: "svc-attr", SupportedEncryptionTypes: desTypes},
			},
		}
		findings := NewWeakEncryptionDESOnDisabledAccountDetector().Detect(context.Background(), data)
		if findings[0].Count != 0 {
			t.Fatalf("active accounts must not be counted by the disabled-account detector, got count=%d", findings[0].Count)
		}
	})

	// Same guard-removal proof as WeakEncryptionDESDetector's test, on the
	// disabled half: -5 carries both DES bits (0x3) in two's complement and
	// must fire here now that the `> 0` guard is gone.
	t.Run("disabled + negative SupportedEncryptionTypes carrying the DES bits fires here", func(t *testing.T) {
		data := &audit.DetectorData{
			Users: []types.User{
				{DN: userDN, SAMAccountName: "svc", Disabled: true, SupportedEncryptionTypes: -5},
			},
		}
		findings := NewWeakEncryptionDESOnDisabledAccountDetector().Detect(context.Background(), data)
		if findings[0].Count != 1 {
			t.Fatalf("a disabled account with a negative SupportedEncryptionTypes carrying the DES bits (0x3) must fire here, got count=%d", findings[0].Count)
		}
	})

	// -8 (0xFFFFFFF8) is negative but carries neither DES bit.
	t.Run("disabled + negative SupportedEncryptionTypes without the DES bits does NOT fire", func(t *testing.T) {
		data := &audit.DetectorData{
			Users: []types.User{
				{DN: userDN, SAMAccountName: "svc", Disabled: true, SupportedEncryptionTypes: -8},
			},
		}
		findings := NewWeakEncryptionDESOnDisabledAccountDetector().Detect(context.Background(), data)
		if findings[0].Count != 0 {
			t.Fatalf("a disabled account with a negative SupportedEncryptionTypes without the DES bits (0x3) must not fire, got count=%d", findings[0].Count)
		}
	})

	// 0x20 (bit 5) is AES256-CTS-HMAC-SHA1-96-SK: it only enforces AES
	// session keys on top of whatever ticket encryption type is actually
	// negotiated, it is not itself a ticket encryption type. 36 (0x24) pairs
	// it with RC4 alone (no DES bit at all), so the attribute carries
	// neither bit of desTypes and this must not fire here either.
	t.Run("disabled + literal attribute 36 (0x24: RC4+AES256-SK, no DES bit) does NOT fire", func(t *testing.T) {
		data := &audit.DetectorData{
			Users: []types.User{
				{DN: userDN, SAMAccountName: "svc", Disabled: true, SupportedEncryptionTypes: 36},
			},
		}
		findings := NewWeakEncryptionDESOnDisabledAccountDetector().Detect(context.Background(), data)
		if findings[0].Count != 0 {
			t.Fatalf("literal 36 (RC4+AES256-SK, no DES bit) on a disabled account must not fire, got count=%d", findings[0].Count)
		}
	})

	t.Run("disabled with neither signal does NOT fire", func(t *testing.T) {
		data := &audit.DetectorData{
			Users: []types.User{{DN: userDN, SAMAccountName: "svc", Disabled: true}},
		}
		findings := NewWeakEncryptionDESOnDisabledAccountDetector().Detect(context.Background(), data)
		if findings[0].Count != 0 {
			t.Fatalf("a disabled account with neither signal must not fire, got count=%d", findings[0].Count)
		}
	})
}
