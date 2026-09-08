// Package azure imports all Azure AD / Entra ID security detectors.
// Risk protection detectors are pro-only (see init_pro.go).
package azure

import (
	_ "github.com/etcsec-com/etc-collector/internal/audit/detectors/azure/applications"
	_ "github.com/etcsec-com/etc-collector/internal/audit/detectors/azure/compliance"
	_ "github.com/etcsec-com/etc-collector/internal/audit/detectors/azure/conditional-access"
	_ "github.com/etcsec-com/etc-collector/internal/audit/detectors/azure/config"
	_ "github.com/etcsec-com/etc-collector/internal/audit/detectors/azure/groups"
	_ "github.com/etcsec-com/etc-collector/internal/audit/detectors/azure/guest-external"
	_ "github.com/etcsec-com/etc-collector/internal/audit/detectors/azure/identity"
	_ "github.com/etcsec-com/etc-collector/internal/audit/detectors/azure/privileged-access"
)
