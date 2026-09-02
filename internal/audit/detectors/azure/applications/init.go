// Package applications imports all application-related detectors.
package applications

import (
	_ "github.com/etcsec-com/etc-collector/internal/audit/detectors/azure/applications/certificates"
	_ "github.com/etcsec-com/etc-collector/internal/audit/detectors/azure/applications/permissions"
	_ "github.com/etcsec-com/etc-collector/internal/audit/detectors/azure/applications/registrations"
	_ "github.com/etcsec-com/etc-collector/internal/audit/detectors/azure/applications/saml"
	_ "github.com/etcsec-com/etc-collector/internal/audit/detectors/azure/applications/secrets"
	_ "github.com/etcsec-com/etc-collector/internal/audit/detectors/azure/applications/service-principals"
)
