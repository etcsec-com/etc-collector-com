// Package trusts contains trust-related security detectors
package trusts

// Encryption type bit flags from msDS-SupportedEncryptionTypes
const (
	EncTypeDESCBCCRC = 0x1
	EncTypeDESCBCMD5 = 0x2
	EncTypeRC4HMAC   = 0x4
	EncTypeAES128    = 0x8
	EncTypeAES256    = 0x10
	EncWeakOnly      = EncTypeDESCBCCRC | EncTypeDESCBCMD5 | EncTypeRC4HMAC
	EncAESTypes      = EncTypeAES128 | EncTypeAES256
)

// Trust attribute flags
const (
	TrustAttributeNonTransitive     = 0x00000001
	TrustAttributeUplevelOnly       = 0x00000002
	TrustAttributeQuarantinedDomain = 0x00000004 // SID filtering enabled
	TrustAttributeForestTransitive  = 0x00000008
	TrustAttributeCrossOrganization = 0x00000010 // Selective authentication
	TrustAttributeWithinForest      = 0x00000020
	TrustAttributeTreatAsExternal   = 0x00000040
	TrustAttributeUsesRC4Encryption = 0x00000080
	TrustAttributeUsesAESKeys       = 0x00000100
	TrustAttributeCrossTLDCheck     = 0x00000200
	TrustAttributePIMTrust          = 0x00000400
)

// Trust direction values
const (
	TrustDirectionDisabled      = 0
	TrustDirectionInbound       = 1
	TrustDirectionOutbound      = 2
	TrustDirectionBidirectional = 3
)
