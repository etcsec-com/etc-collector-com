// Package ad imports all Active Directory security detectors.
// ADCS (ESC1-11) and attack-path detectors are pro-only (see init_pro.go).
package ad

import (
	// Core detector categories — register themselves via init()
	_ "github.com/etcsec-com/etc-collector/internal/audit/detectors/ad/accounts"
	_ "github.com/etcsec-com/etc-collector/internal/audit/detectors/ad/advanced"
	_ "github.com/etcsec-com/etc-collector/internal/audit/detectors/ad/compliance"
	_ "github.com/etcsec-com/etc-collector/internal/audit/detectors/ad/computers"
	_ "github.com/etcsec-com/etc-collector/internal/audit/detectors/ad/gpo"
	_ "github.com/etcsec-com/etc-collector/internal/audit/detectors/ad/groups"
	_ "github.com/etcsec-com/etc-collector/internal/audit/detectors/ad/kerberos"
	_ "github.com/etcsec-com/etc-collector/internal/audit/detectors/ad/monitoring"
	_ "github.com/etcsec-com/etc-collector/internal/audit/detectors/ad/network"
	_ "github.com/etcsec-com/etc-collector/internal/audit/detectors/ad/password"
	_ "github.com/etcsec-com/etc-collector/internal/audit/detectors/ad/permissions"
	_ "github.com/etcsec-com/etc-collector/internal/audit/detectors/ad/trusts"
)
