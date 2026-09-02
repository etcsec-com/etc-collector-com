// Package attackpaths imports all attack-path detectors
package attackpaths

import (
	_ "github.com/etcsec-com/etc-collector/internal/audit/detectors/ad/attack-paths/critical"
	_ "github.com/etcsec-com/etc-collector/internal/audit/detectors/ad/attack-paths/high"
	_ "github.com/etcsec-com/etc-collector/internal/audit/detectors/ad/attack-paths/medium"
)
