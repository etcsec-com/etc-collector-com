package mfa

import (
	"context"
	"fmt"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// MFAUnusualLocationDetector flags risky sign-ins (Identity Protection) that
// originated from a geography not covered by any configured Named Location.
// Partially matches Purple Knight SI000155 (location context on MFA methods).
type MFAUnusualLocationDetector struct {
	audit.BaseDetector
}

func NewMFAUnusualLocationDetector() *MFAUnusualLocationDetector {
	return &MFAUnusualLocationDetector{
		BaseDetector: audit.NewBaseDetector("MFA_UNUSUAL_LOCATION", audit.CategoryIdentity),
	}
}

func (d *MFAUnusualLocationDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// Build the set of country codes referenced by any named location.
	knownCountries := make(map[string]bool)
	hasAnyCountryScope := false
	for _, nl := range data.AzureNamedLocations {
		for _, cc := range nl.CountriesAndRegions {
			knownCountries[strings.ToUpper(cc)] = true
			hasAnyCountryScope = true
		}
	}

	pairs := make([]string, 0)
	countByUser := make(map[string]int)

	for _, rs := range data.AzureRiskySignIns {
		// Focus on atRisk / confirmed state - dismissed / remediated already handled.
		if rs.RiskState != "" && rs.RiskState != "atRisk" && rs.RiskState != "confirmedCompromised" {
			continue
		}
		// Heuristic: if any named location defines countries, treat a sign-in
		// from outside that set as unusual. If no country scoping exists at all,
		// fall back to flagging anything Identity Protection has marked high risk.
		flag := false
		loc := strings.ToUpper(strings.TrimSpace(rs.Location))
		switch {
		case hasAnyCountryScope && loc != "" && !knownCountries[loc]:
			flag = true
		case !hasAnyCountryScope && rs.RiskLevel == "high":
			flag = true
		}
		if !flag {
			continue
		}
		countByUser[rs.UserPrincipalName]++
		pairs = append(pairs, fmt.Sprintf("user=%s ip=%s location=%s risk=%s",
			rs.UserPrincipalName, rs.IPAddress, rs.Location, rs.RiskLevel))
	}

	finding := types.Finding{
		Type:     d.ID(),
		Severity: types.SeverityMedium,
		Category: string(d.Category()),
		Title:    "MFA sign-in from unusual geolocation",
		Description: "Identity Protection surfaced risky sign-ins from geographies outside " +
			"the tenant's Named Locations. These may indicate credential theft or travel " +
			"outside approved regions.",
		Count: len(pairs),
		Details: map[string]interface{}{
			"recommendation": "Investigate each sign-in. Add expected geographies to Named Locations or remediate the user in Identity Protection.",
			"byUser":         countByUser,
			"pairs":          pairs,
		},
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewMFAUnusualLocationDetector())
}
