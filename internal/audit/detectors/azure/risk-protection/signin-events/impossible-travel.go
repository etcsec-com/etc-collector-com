package signinevents

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

type ImpossibleTravelDetector struct {
	audit.BaseDetector
}

func NewImpossibleTravelDetector() *ImpossibleTravelDetector {
	return &ImpossibleTravelDetector{BaseDetector: audit.NewBaseDetector(RISK_IMPOSSIBLE_TRAVEL, audit.CategoryRiskProtection)}
}

func (d *ImpossibleTravelDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	severity := types.SeverityHigh
	finding := types.Finding{
		Type:        d.ID(),
		Severity:    severity,
		Category:    string(d.Category()),
		Title:       "Impossible Travel Sign-In Pattern",
		Description: "A user signed in from distant countries too quickly for normal travel.",
		Count:       0,
	}
	if len(data.AzureSignInLogs) == 0 {
		return []types.Finding{finding}
	}

	admins := buildAdminUserSet(data.AzureRoleAssignments)
	var affected []types.AffectedEntity
	hasAdmin := false
	for _, events := range groupEventsByUser(data.AzureSignInLogs) {
		sortEvents(events)
		type bestPair struct {
			from     *types.SignInLog
			to       *types.SignInLog
			deltaSec int64
			distance float64
			speed    float64
			isAdmin  bool
		}
		var best bestPair
		for i := 1; i < len(events); i++ {
			from := events[i-1]
			to := events[i]
			if isCrossTenant(from) || isCrossTenant(to) {
				continue
			}
			fromCountry := locationCountry(from)
			toCountry := locationCountry(to)
			distance, ok := distanceBetweenCountries(fromCountry, toCountry)
			if !ok {
				continue
			}
			delta := to.CreatedDateTime.Sub(from.CreatedDateTime)
			if delta <= 0 {
				continue
			}
			speed := distance / delta.Hours()
			if speed <= impossibleTravelMinKmh {
				continue
			}
			isAdmin := admins[strings.ToLower(strings.TrimSpace(to.UserID))] || admins[strings.ToLower(strings.TrimSpace(to.UserPrincipalName))]
			if speed > best.speed {
				best = bestPair{
					from:     from,
					to:       to,
					deltaSec: int64(delta.Seconds()),
					distance: distance,
					speed:    speed,
					isAdmin:  isAdmin,
				}
			}
		}
		if best.speed == 0 {
			continue
		}
		finding.Count++
		if best.isAdmin {
			hasAdmin = true
		}
		if data.IncludeDetails {
			affected = append(affected, newUserRiskEntity(best.to, map[string]any{
				"isAdmin":          best.isAdmin,
				"fromCity":         best.from.Location.City,
				"fromCountry":      best.from.Location.CountryOrRegion,
				"toCity":           best.to.Location.City,
				"toCountry":        best.to.Location.CountryOrRegion,
				"deltaSeconds":     best.deltaSec,
				"distanceKm":       round1(best.distance),
				"computedSpeedKmh": round1(best.speed),
				"fromIp":           best.from.IPAddress,
				"toIp":             best.to.IPAddress,
			}))
		}
	}
	if hasAdmin {
		finding.Severity = types.SeverityCritical
		finding.Description = "An administrative user signed in from distant countries too quickly for normal travel."
	}
	sortAffectedUsers(affected)
	finding.AffectedEntities = affected
	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewImpossibleTravelDetector())
}
