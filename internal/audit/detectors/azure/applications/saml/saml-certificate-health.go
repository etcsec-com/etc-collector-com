package saml

import (
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// SAML signing certificate detectors audit token-signing credentials on service
// principals. Matches Purple Knight SI000117.
//
// The detectors read existing ServicePrincipal.KeyCredentials whose Usage is
// "Sign" (or empty) - those are the token-signing certificates used for SAML
// SSO. No separate type or new API call is required; the data is already
// fetched by the Azure provider and now includes Thumbprint + Usage.
//
// Each of the three checks (expired, expiring soon, long lifetime) now lives
// in its own file (saml-certificate-expired.go, saml-certificate-expiring-
// soon.go, saml-certificate-long-lifetime.go). isSigningCert below is
// genuinely shared across all three and stays here.

// isSigningCert returns true when the credential is a token-signing certificate
// eligible for the SAML checks.
func isSigningCert(kc types.AppCredential) bool {
	if kc.Type != "certificate" {
		return false
	}
	// Empty Usage is treated as potentially signing (defensive default).
	return kc.Usage == "" || kc.Usage == "Sign" || kc.Usage == "Verify"
}
