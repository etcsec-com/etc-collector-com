// Package groups imports all group-related detectors
package groups

import (
	_ "github.com/etcsec-com/etc-collector/internal/audit/detectors/ad/groups/gmsa"
	_ "github.com/etcsec-com/etc-collector/internal/audit/detectors/ad/groups/membership"
	_ "github.com/etcsec-com/etc-collector/internal/audit/detectors/ad/groups/nesting"
	_ "github.com/etcsec-com/etc-collector/internal/audit/detectors/ad/groups/privileged"
	_ "github.com/etcsec-com/etc-collector/internal/audit/detectors/ad/groups/size"
)
