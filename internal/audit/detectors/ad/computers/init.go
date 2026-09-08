// Package computers imports all computer-related detectors
package computers

import (
	_ "github.com/etcsec-com/etc-collector/internal/audit/detectors/ad/computers/delegation"
	_ "github.com/etcsec-com/etc-collector/internal/audit/detectors/ad/computers/obsolete"
	_ "github.com/etcsec-com/etc-collector/internal/audit/detectors/ad/computers/organization"
	_ "github.com/etcsec-com/etc-collector/internal/audit/detectors/ad/computers/other"
	_ "github.com/etcsec-com/etc-collector/internal/audit/detectors/ad/computers/rodc"
	_ "github.com/etcsec-com/etc-collector/internal/audit/detectors/ad/computers/security"
	_ "github.com/etcsec-com/etc-collector/internal/audit/detectors/ad/computers/status"
)
