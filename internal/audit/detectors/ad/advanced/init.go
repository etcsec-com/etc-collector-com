// Package advanced imports all advanced detectors.
// Advanced ADCS detectors are pro-only (see init_pro.go).
package advanced

import (
	_ "github.com/etcsec-com/etc-collector/internal/audit/detectors/ad/advanced/credentials"
	_ "github.com/etcsec-com/etc-collector/internal/audit/detectors/ad/advanced/domain-policy"
	_ "github.com/etcsec-com/etc-collector/internal/audit/detectors/ad/advanced/laps"
	_ "github.com/etcsec-com/etc-collector/internal/audit/detectors/ad/advanced/monitoring"
	_ "github.com/etcsec-com/etc-collector/internal/audit/detectors/ad/advanced/other"
	_ "github.com/etcsec-com/etc-collector/internal/audit/detectors/ad/advanced/replication"
	_ "github.com/etcsec-com/etc-collector/internal/audit/detectors/ad/advanced/signing"
)
