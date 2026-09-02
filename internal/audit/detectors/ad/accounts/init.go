// Package accounts imports all account-related detectors
package accounts

import (
	_ "github.com/etcsec-com/etc-collector/internal/audit/detectors/ad/accounts/advanced"
	_ "github.com/etcsec-com/etc-collector/internal/audit/detectors/ad/accounts/patterns"
	_ "github.com/etcsec-com/etc-collector/internal/audit/detectors/ad/accounts/privileged"
	_ "github.com/etcsec-com/etc-collector/internal/audit/detectors/ad/accounts/service-accounts"
	_ "github.com/etcsec-com/etc-collector/internal/audit/detectors/ad/accounts/status"
)
