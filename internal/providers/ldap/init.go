package ldap

import "github.com/etcsec-com/etc-collector/internal/providers"

// init registers the LDAP error classifier with the providers registry so
// that errors wrapped via providers.NewProviderError(ProviderTypeLDAP, ...)
// are passed through Classify() automatically. Without this, search-phase
// errors (post-bind) would lose their structured code (e.g., a Result Code
// 10 "Referral" for a bad base DN would not be reported as
// LDAP_REFERRAL_BAD_BASE_DN).
func init() {
	providers.RegisterClassifier(providers.ProviderTypeLDAP, func(e error) error {
		return Classify(e)
	})
}
