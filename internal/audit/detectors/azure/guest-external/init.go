// Package guestexternal imports all guest and external user detectors.
package guestexternal

import (
	_ "github.com/etcsec-com/etc-collector/internal/audit/detectors/azure/guest-external/access"
	_ "github.com/etcsec-com/etc-collector/internal/audit/detectors/azure/guest-external/b2b"
	_ "github.com/etcsec-com/etc-collector/internal/audit/detectors/azure/guest-external/governance"
)
