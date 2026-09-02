package types

// UserAccountControl (UAC) flag constants for Active Directory.
// Reference: https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/useraccountcontrol-manipulate
const (
	UACAccountDisabled            = 0x000002
	UACPasswordNotRequired        = 0x000020
	UACNormalAccount              = 0x000200
	UACDontExpirePassword         = 0x010000
	UACSmartCardRequired          = 0x040000
	UACTrustedForDelegation       = 0x080000  // Unconstrained delegation
	UACNotDelegated               = 0x100000  // Account is sensitive and cannot be delegated
	UACDontRequirePreauth         = 0x400000  // AS-REP roasting
	UACTrustedToAuthForDelegation = 0x1000000 // Protocol transition (constrained delegation with S4U2Self)
)
