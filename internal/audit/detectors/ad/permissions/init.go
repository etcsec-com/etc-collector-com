// Package permissions imports all permission-related detectors
package permissions

import (
	_ "github.com/etcsec-com/etc-collector/internal/audit/detectors/ad/permissions/computer"
	_ "github.com/etcsec-com/etc-collector/internal/audit/detectors/ad/permissions/dangerous"
	_ "github.com/etcsec-com/etc-collector/internal/audit/detectors/ad/permissions/moderate"
	_ "github.com/etcsec-com/etc-collector/internal/audit/detectors/ad/permissions/organization"
)
