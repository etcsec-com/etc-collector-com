package types

import "testing"

// TestUACConstants pins the exact numeric value of every UserAccountControl
// flag constant against MS-ADTS 2.2.16 / the Microsoft UAC manipulation
// reference. UACInterdomainTrustAccount in particular is read by the
// PASSWORD_NOT_REQUIRED detectors to exclude interdomain trust accounts
// (KB 305144): a drift here (e.g. to 0x900, which also carries bit 0x100)
// would silently change which accounts those detectors exclude, with no
// other test in the codebase comparing this constant to its documented bit.
func TestUACConstants(t *testing.T) {
	cases := []struct {
		name string
		got  int
		want int
	}{
		{"UACAccountDisabled", UACAccountDisabled, 0x000002},
		{"UACPasswordNotRequired", UACPasswordNotRequired, 0x000020},
		{"UACEncryptedTextPasswordAllowed", UACEncryptedTextPasswordAllowed, 0x000080},
		{"UACNormalAccount", UACNormalAccount, 0x000200},
		{"UACInterdomainTrustAccount", UACInterdomainTrustAccount, 0x000800},
		{"UACDontExpirePassword", UACDontExpirePassword, 0x010000},
		{"UACSmartCardRequired", UACSmartCardRequired, 0x040000},
		{"UACTrustedForDelegation", UACTrustedForDelegation, 0x080000},
		{"UACNotDelegated", UACNotDelegated, 0x100000},
		{"UACDontRequirePreauth", UACDontRequirePreauth, 0x400000},
		{"UACTrustedToAuthForDelegation", UACTrustedToAuthForDelegation, 0x1000000},
	}

	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s = %#x, want %#x", c.name, c.got, c.want)
		}
	}
}
