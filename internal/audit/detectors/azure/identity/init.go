// Package identity imports all identity-related Azure detectors.
package identity

import (
	_ "github.com/etcsec-com/etc-collector/internal/audit/detectors/azure/identity/auth-methods"
	_ "github.com/etcsec-com/etc-collector/internal/audit/detectors/azure/identity/hybrid"
	_ "github.com/etcsec-com/etc-collector/internal/audit/detectors/azure/identity/legacy-auth"
	_ "github.com/etcsec-com/etc-collector/internal/audit/detectors/azure/identity/lifecycle"
	_ "github.com/etcsec-com/etc-collector/internal/audit/detectors/azure/identity/mfa"
	_ "github.com/etcsec-com/etc-collector/internal/audit/detectors/azure/identity/password-policy"
	_ "github.com/etcsec-com/etc-collector/internal/audit/detectors/azure/identity/sspr"
)
