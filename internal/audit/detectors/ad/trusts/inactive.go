package trusts

import (
	"context"
	"time"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// trustInactiveThresholdDays - a trust's inter-domain secret auto-rotates
// every 30 days in each direction while the trust is alive (ANSSI-PA-099
// R42, p.55: "Les mots de passe des TDO sont renouvelés automatiquement
// tous les trente jours" - the 30-day machine-account interval MS-NRPC
// documents is a different account class), so a secret this stale in
// EVERY direction the trust actually has indicates
// either broken rotation or an abandoned trust nobody maintains. 180 days is
// a product choice; no ANSSI or Microsoft source fixes this figure for
// trusts specifically.
const trustInactiveThresholdDays = 180

// InactiveDetector detects inactive trust relationships
type InactiveDetector struct {
	audit.BaseDetector
}

// NewInactiveDetector creates a new detector
func NewInactiveDetector() *InactiveDetector {
	return &InactiveDetector{
		BaseDetector: audit.NewBaseDetector("TRUST_INACTIVE", audit.CategoryTrusts),
	}
}

// trustDirectionAge resolves the date to use for one direction of a trust's
// secret: an exact reading (types.Trust's already-resolved
// replmetadata/trust_account date) first, falling back to the TDO's
// whenChanged as a bound-only signal (never a source of "recent" - see
// types.Trust.WhenChanged). ok is false only when neither is available at
// all, in which case the caller must stay silent on this direction rather
// than guess.
func trustDirectionAge(exactDate time.Time, exactSource string, whenChanged time.Time) (date time.Time, source string, ok bool) {
	if exactSource != "" {
		return exactDate, exactSource, true
	}
	if !whenChanged.IsZero() {
		return whenChanged, "whenChanged bound", true
	}
	return time.Time{}, "", false
}

// Detect executes the detection
func (d *InactiveDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affectedNames []string
	var trustDetails []map[string]interface{}

	for _, t := range data.Trusts {
		// MIT realms have no automatic rotation to go stale (netdom
		// /PasswordT / ksetup set the key by hand); flagging one as
		// "inactive" would penalize the only trust type that was never
		// expected to rotate on its own.
		if t.TrustProtocolType == "MIT" {
			continue
		}

		hasOutgoing := t.TrustDirection == "Outbound" || t.TrustDirection == "Bidirectional"
		hasIncoming := t.TrustDirection == "Inbound" || t.TrustDirection == "Bidirectional"
		if !hasOutgoing && !hasIncoming {
			// Disabled trust (trustDirection 0): no direction rotates, so
			// none can be "inactive" either.
			continue
		}

		allStale := true
		var directions []map[string]interface{}

		if hasOutgoing {
			date, source, ok := trustDirectionAge(t.OutgoingPasswordDate, t.OutgoingPasswordSource, t.WhenChanged)
			if !ok {
				allStale = false
			} else {
				age := data.Now.Sub(date).Hours() / 24
				if age < trustInactiveThresholdDays {
					allStale = false
				}
				directions = append(directions, map[string]interface{}{
					"direction": "outgoing",
					"date":      date.UTC().Format(time.RFC3339),
					"source":    source,
					"ageDays":   int(age),
				})
			}
		}
		if hasIncoming {
			date, source, ok := trustDirectionAge(t.IncomingPasswordDate, t.IncomingPasswordSource, t.WhenChanged)
			if !ok {
				allStale = false
			} else {
				age := data.Now.Sub(date).Hours() / 24
				if age < trustInactiveThresholdDays {
					allStale = false
				}
				directions = append(directions, map[string]interface{}{
					"direction": "incoming",
					"date":      date.UTC().Format(time.RFC3339),
					"source":    source,
					"ageDays":   int(age),
				})
			}
		}

		if allStale {
			affectedNames = append(affectedNames, t.TargetDomain)
			for _, dd := range directions {
				dd["targetDomain"] = t.TargetDomain
				trustDetails = append(trustDetails, dd)
			}
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "Inactive Trust Relationship",
		Description: "Trust relationship's secret has not been rotated in over 180 days in any of its available directions. May indicate an abandoned or forgotten trust that should be reviewed for necessity.",
		Count:       len(affectedNames),
	}

	if len(affectedNames) > 0 {
		finding.Details = map[string]interface{}{
			"recommendation": "Review necessity of inactive trusts. Remove trusts that are no longer needed to reduce attack surface.",
			"trusts":         trustDetails,
		}
	}

	if data.IncludeDetails && len(affectedNames) > 0 {
		entities := make([]types.AffectedEntity, len(affectedNames))
		for i, name := range affectedNames {
			entities[i] = types.AffectedEntity{
				Type: "trust",
				Name: name,
			}
		}
		finding.AffectedEntities = entities
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewInactiveDetector())
}
