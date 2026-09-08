// Package privilegedaccess imports all privileged access detectors.
package privilegedaccess

import (
	_ "github.com/etcsec-com/etc-collector/internal/audit/detectors/azure/privileged-access/emergency"
	_ "github.com/etcsec-com/etc-collector/internal/audit/detectors/azure/privileged-access/membership"
	_ "github.com/etcsec-com/etc-collector/internal/audit/detectors/azure/privileged-access/pim"
	_ "github.com/etcsec-com/etc-collector/internal/audit/detectors/azure/privileged-access/roles"
)
