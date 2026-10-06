package kerberos

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// TestWeakEncryptionDES covers the two-branch disjunction (UAC bit
// USE_DES_KEY_ONLY vs msDS-SupportedEncryptionTypes DES bits) and the
// disabled-account exclusion added by this split. Measured live on DC01
// (Server 2022) before this split existed: the BIT branch was 19 accounts,
// all disabled; the ATTRIBUTE branch (rule 1.2.840.113556.1.4.804 OR-test on
// value 3) was 2 accounts, both active; the two branches did not overlap
// (measured, not assumed). Neither case this
// detector needs to exclude or include existed naturally in both states, so
// a fixture user was planted and flipped active->disabled in the same
// session for each branch; cross-checked DN-by-DN against
// `public/dist/etc-collector audit ad` (pre-split binary): 23/23 identical,
// zero false positive, zero blind spot. See
// docs/security-validation/results/weak-encryption-des-t243/VERDICT.md.
func TestWeakEncryptionDES(t *testing.T) {
	userDN := "CN=svc,OU=Services,DC=test,DC=local"

	t.Run("UAC bit branch fires", func(t *testing.T) {
		data := &audit.DetectorData{
			Users: []types.User{
				{DN: userDN, SAMAccountName: "svc", UserAccountControl: uacUseDESKeyOnly},
			},
			IncludeDetails: true,
		}
		findings := NewWeakEncryptionDESDetector().Detect(context.Background(), data)
		if len(findings) != 1 || findings[0].Count != 1 {
			t.Fatalf("UAC bit branch must fire, got %+v", findings)
		}
		if findings[0].Severity != types.SeverityHigh {
			t.Fatalf("active half must be High, got %s", findings[0].Severity)
		}
	})

	t.Run("attribute branch fires", func(t *testing.T) {
		data := &audit.DetectorData{
			Users: []types.User{
				{DN: userDN, SAMAccountName: "svc", SupportedEncryptionTypes: desTypes},
			},
			IncludeDetails: true,
		}
		findings := NewWeakEncryptionDESDetector().Detect(context.Background(), data)
		if len(findings) != 1 || findings[0].Count != 1 {
			t.Fatalf("attribute branch must fire, got %+v", findings)
		}
	})

	t.Run("attribute branch fires with RC4/AES also set (not DES-exclusive)", func(t *testing.T) {
		data := &audit.DetectorData{
			Users: []types.User{
				{DN: userDN, SAMAccountName: "svc", SupportedEncryptionTypes: 0x7}, // DES_CBC_CRC|DES_CBC_MD5|RC4, matching the two active DES+RC4 accounts measured on the lab
			},
		}
		findings := NewWeakEncryptionDESDetector().Detect(context.Background(), data)
		if findings[0].Count != 1 {
			t.Fatalf("attribute branch must fire even when a non-DES etype is also configured, got count=%d", findings[0].Count)
		}
	})

	// Literal-value cases: the subtests above build their fixture from the
	// very same uacUseDESKeyOnly/desTypes constants the code checks against,
	// so a drift in either constant's numeric value could never make them
	// fail - the same structural blindness that let the LAPS GUID constant
	// stay wrong for months (fixture and check both read types.GUIDLAPSPassword).
	// These use hardcoded literals distinct from the constants, pinned to the
	// real Kerberos etype bits ([MS-KILE] 2.2.7: DES_CBC_CRC=0x1,
	// DES_CBC_MD5=0x2, RC4_HMAC_MD5=0x4) and the real UAC bit layout.
	t.Run("literal UAC bit 0x200000 fires (constant-independent)", func(t *testing.T) {
		data := &audit.DetectorData{
			Users: []types.User{
				{DN: userDN, SAMAccountName: "svc", UserAccountControl: 0x200000},
			},
		}
		findings := NewWeakEncryptionDESDetector().Detect(context.Background(), data)
		if findings[0].Count != 1 {
			t.Fatalf("literal 0x200000 (USE_DES_KEY_ONLY) must fire, got count=%d", findings[0].Count)
		}
	})

	t.Run("literal UAC bit 0x100000 (adjacent NOT_DELEGATED, not DES) does NOT fire", func(t *testing.T) {
		data := &audit.DetectorData{
			Users: []types.User{
				{DN: userDN, SAMAccountName: "svc", UserAccountControl: 0x100000},
			},
		}
		findings := NewWeakEncryptionDESDetector().Detect(context.Background(), data)
		if findings[0].Count != 0 {
			t.Fatalf("an adjacent UAC bit (0x100000, not USE_DES_KEY_ONLY) must not fire, got count=%d", findings[0].Count)
		}
	})

	t.Run("literal attribute bit 0x1 (DES_CBC_CRC alone) fires", func(t *testing.T) {
		data := &audit.DetectorData{
			Users: []types.User{
				{DN: userDN, SAMAccountName: "svc", SupportedEncryptionTypes: 0x1},
			},
		}
		findings := NewWeakEncryptionDESDetector().Detect(context.Background(), data)
		if findings[0].Count != 1 {
			t.Fatalf("literal 0x1 (DES_CBC_CRC alone) must fire, got count=%d", findings[0].Count)
		}
	})

	t.Run("literal attribute bit 0x2 (DES_CBC_MD5 alone) fires", func(t *testing.T) {
		data := &audit.DetectorData{
			Users: []types.User{
				{DN: userDN, SAMAccountName: "svc", SupportedEncryptionTypes: 0x2},
			},
		}
		findings := NewWeakEncryptionDESDetector().Detect(context.Background(), data)
		if findings[0].Count != 1 {
			t.Fatalf("literal 0x2 (DES_CBC_MD5 alone) must fire, got count=%d", findings[0].Count)
		}
	})

	t.Run("literal attribute bit 0x4 (RC4 alone, no DES bit) does NOT fire", func(t *testing.T) {
		data := &audit.DetectorData{
			Users: []types.User{
				{DN: userDN, SAMAccountName: "svc", SupportedEncryptionTypes: 0x4},
			},
		}
		findings := NewWeakEncryptionDESDetector().Detect(context.Background(), data)
		if findings[0].Count != 0 {
			t.Fatalf("literal 0x4 (RC4 alone, no DES bit) must not fire, got count=%d", findings[0].Count)
		}
	})

	t.Run("both branches set counts once, not twice", func(t *testing.T) {
		data := &audit.DetectorData{
			Users: []types.User{
				{DN: userDN, SAMAccountName: "svc", UserAccountControl: uacUseDESKeyOnly, SupportedEncryptionTypes: desTypes},
			},
		}
		findings := NewWeakEncryptionDESDetector().Detect(context.Background(), data)
		if findings[0].Count != 1 {
			t.Fatalf("one account with both signals must count once, got count=%d", findings[0].Count)
		}
	})

	// 0x20 (bit 5) is AES256-CTS-HMAC-SHA1-96-SK: it only enforces AES
	// session keys on top of whatever ticket encryption type is actually
	// negotiated, it is not itself a ticket encryption type. 36 (0x24) pairs
	// it with RC4 alone (no DES bit at all), so the attribute carries neither
	// bit of desTypes and this must not fire.
	t.Run("literal attribute 36 (0x24: RC4+AES256-SK, no DES bit) does NOT fire", func(t *testing.T) {
		data := &audit.DetectorData{
			Users: []types.User{
				{DN: userDN, SAMAccountName: "svc", SupportedEncryptionTypes: 36},
			},
		}
		findings := NewWeakEncryptionDESDetector().Detect(context.Background(), data)
		if findings[0].Count != 0 {
			t.Fatalf("literal 36 (RC4+AES256-SK, no DES bit) must not fire, got count=%d", findings[0].Count)
		}
	})

	t.Run("neither branch set does NOT fire", func(t *testing.T) {
		data := &audit.DetectorData{
			Users: []types.User{{DN: userDN, SAMAccountName: "svc"}},
		}
		findings := NewWeakEncryptionDESDetector().Detect(context.Background(), data)
		if findings[0].Count != 0 {
			t.Fatalf("an account with neither signal must not fire, got count=%d", findings[0].Count)
		}
	})

	t.Run("disabled account, UAC bit branch, does NOT fire here", func(t *testing.T) {
		data := &audit.DetectorData{
			Users: []types.User{
				{DN: userDN, SAMAccountName: "svc", Disabled: true, UserAccountControl: uacUseDESKeyOnly},
			},
		}
		findings := NewWeakEncryptionDESDetector().Detect(context.Background(), data)
		if findings[0].Count != 0 {
			t.Fatalf("disabled account (bit branch) must be excluded from the active detector, got count=%d", findings[0].Count)
		}
	})

	t.Run("disabled account, attribute branch, does NOT fire here", func(t *testing.T) {
		data := &audit.DetectorData{
			Users: []types.User{
				{DN: userDN, SAMAccountName: "svc", Disabled: true, SupportedEncryptionTypes: desTypes},
			},
		}
		findings := NewWeakEncryptionDESDetector().Detect(context.Background(), data)
		if findings[0].Count != 0 {
			t.Fatalf("disabled account (attribute branch) must be excluded from the active detector, got count=%d", findings[0].Count)
		}
	})

	// There is no longer a `SupportedEncryptionTypes > 0` guard here: AD
	// accepts (measured live on DC01, ldapmodify, no schema rejection) a
	// negative msDS-SupportedEncryptionTypes value, and Go's getIntAttr
	// round-trips it unchanged via strconv.Atoi. -5 has both DES bits (0x3)
	// set in two's complement, so `-5&desTypes != 0` is true; a `-5 > 0`
	// guard would wrongly suppress this exact case.
	t.Run("negative SupportedEncryptionTypes carrying the DES bits fires", func(t *testing.T) {
		data := &audit.DetectorData{
			Users: []types.User{
				{DN: userDN, SAMAccountName: "svc", SupportedEncryptionTypes: -5},
			},
		}
		findings := NewWeakEncryptionDESDetector().Detect(context.Background(), data)
		if findings[0].Count != 1 {
			t.Fatalf("a negative SupportedEncryptionTypes carrying the DES bits (0x3) must fire, got count=%d", findings[0].Count)
		}
	})

	// -8 (0xFFFFFFF8) is negative but carries neither DES bit: distinguishes
	// "fires on any negative value" from "fires on the DES bits regardless of
	// sign" - removing the guard must not turn this into a fire-on-negative
	// detector.
	t.Run("negative SupportedEncryptionTypes without the DES bits does NOT fire", func(t *testing.T) {
		data := &audit.DetectorData{
			Users: []types.User{
				{DN: userDN, SAMAccountName: "svc", SupportedEncryptionTypes: -8},
			},
		}
		findings := NewWeakEncryptionDESDetector().Detect(context.Background(), data)
		if findings[0].Count != 0 {
			t.Fatalf("a negative SupportedEncryptionTypes without the DES bits (0x3) must not fire, got count=%d", findings[0].Count)
		}
	})
}

// TestWeakEncryptionDES_PartitionIsExhaustive covers both branches, active
// and disabled, ensuring the two detectors classify every account exactly
// once - no account counted twice, no account dropped.
func TestWeakEncryptionDES_PartitionIsExhaustive(t *testing.T) {
	users := []types.User{
		{DN: "CN=active-bit", SAMAccountName: "active-bit", UserAccountControl: uacUseDESKeyOnly},
		{DN: "CN=active-attr", SAMAccountName: "active-attr", SupportedEncryptionTypes: desTypes},
		{DN: "CN=disabled-bit", SAMAccountName: "disabled-bit", Disabled: true, UserAccountControl: uacUseDESKeyOnly},
		{DN: "CN=disabled-attr", SAMAccountName: "disabled-attr", Disabled: true, SupportedEncryptionTypes: desTypes},
		{DN: "CN=neither", SAMAccountName: "neither"},
	}
	data := &audit.DetectorData{Users: users, IncludeDetails: true}

	active := NewWeakEncryptionDESDetector().Detect(context.Background(), data)
	disabled := NewWeakEncryptionDESOnDisabledAccountDetector().Detect(context.Background(), data)

	if active[0].Count != 2 {
		t.Fatalf("active half: want 2 (active-bit, active-attr), got %d", active[0].Count)
	}
	if disabled[0].Count != 2 {
		t.Fatalf("disabled half: want 2 (disabled-bit, disabled-attr), got %d", disabled[0].Count)
	}
	if active[0].Count+disabled[0].Count != 4 {
		t.Fatalf("partition must total 4 affected accounts (5 users minus 1 with neither signal), got %d", active[0].Count+disabled[0].Count)
	}
}
