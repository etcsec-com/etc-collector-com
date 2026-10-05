package adcs

import (
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// EKU OIDs
const (
	EKUClientAuth              = "1.3.6.1.5.5.7.3.2"        // Client Authentication
	EKUSmartcardLogon          = "1.3.6.1.4.1.311.20.2.2"   // Smart Card Logon
	EKUPKINITClientAuth        = "1.3.6.1.5.2.3.4"          // PKINIT Client Authentication
	EKUAnyPurpose              = "2.5.29.37.0"              // Any Purpose
	EKUCertificateRequestAgent = "1.3.6.1.4.1.311.20.2.1"   // Certificate Request Agent
	EKUCertRequestAgent        = EKUCertificateRequestAgent // Alias
)

// Certificate template flags
const (
	CTFlagEnrolleeSuppliesSubject = 0x00000001 // CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT
	CTFlagPendAllRequests         = 0x00000002 // CT_FLAG_PEND_ALL_REQUESTS
	CTFlagNoSecurityExtension     = 0x00080000 // CT_FLAG_NO_SECURITY_EXTENSION
)

// HasAuthenticationEKU checks if the EKU list contains authentication capabilities
func HasAuthenticationEKU(ekus []string) bool {
	for _, eku := range ekus {
		switch eku {
		case EKUClientAuth, EKUSmartcardLogon, EKUPKINITClientAuth:
			return true
		}
	}
	return false
}

// ContainsEKU checks if a specific EKU is in the list
func ContainsEKU(ekus []string, target string) bool {
	for _, eku := range ekus {
		if eku == target {
			return true
		}
	}
	return false
}

// templateEnrollableByUnprivileged reports whether a non-privileged principal
// holds an enrollment right (Certificate-Enrollment, Certificate-AutoEnrollment,
// or a full-control mask) on the certificate template at dn. ESC1/ESC2/ESC3 are
// only exploitable when such a grant exists; a template only enrollable by
// admins is not a privilege escalation path.
func templateEnrollableByUnprivileged(dn string, acls []types.ACLEntry) bool {
	for _, acl := range acls {
		if acl.ObjectDN != dn {
			continue
		}
		if strings.ToLower(acl.AceType) == "deny" {
			continue
		}

		grantsEnrollment := acl.ObjectType == types.GUIDCertificateEnrollment ||
			acl.ObjectType == types.GUIDCertificateAutoenrollment ||
			(acl.AccessMask&GenericAll) != 0
		if !grantsEnrollment {
			continue
		}

		if !audit.IsPrivilegedSID(acl.Trustee) {
			return true
		}
	}
	return false
}
