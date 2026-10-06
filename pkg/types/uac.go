package types

// UserAccountControl (UAC) flag constants for Active Directory.
// Reference: https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/useraccountcontrol-manipulate-account-properties
const (
	UACAccountDisabled              = 0x000002
	UACPasswordNotRequired          = 0x000020
	UACEncryptedTextPasswordAllowed = 0x000080 // Password is persisted using reversible encryption (recoverable, not just weak)
	UACNormalAccount                = 0x000200
	UACDontExpirePassword           = 0x010000
	UACSmartCardRequired            = 0x040000
	UACTrustedForDelegation         = 0x080000  // Unconstrained delegation
	UACNotDelegated                 = 0x100000  // Account is sensitive and cannot be delegated
	UACDontRequirePreauth           = 0x400000  // AS-REP roasting
	UACTrustedToAuthForDelegation   = 0x1000000 // Protocol transition (constrained delegation with S4U2Self)
	UACInterdomainTrustAccount      = 0x000800  // Interdomain trust account; Windows sets PASSWD_NOTREQD on it by default (KB 305144)
)
