// Package riskprotection imports all risk protection detectors.
package riskprotection

import (
	_ "github.com/etcsec-com/etc-collector/internal/audit/detectors/azure/risk-protection/detection"
	_ "github.com/etcsec-com/etc-collector/internal/audit/detectors/azure/risk-protection/response"
	_ "github.com/etcsec-com/etc-collector/internal/audit/detectors/azure/risk-protection/signin-events"
)
