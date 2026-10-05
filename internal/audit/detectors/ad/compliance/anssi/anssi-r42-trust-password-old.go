package anssi

import (
	"context"
	"fmt"
	"time"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// ANSSI-PA-099 R42 - Trust account password not rotated.
//
// # R42 - Contrôler le renouvellement des mots de passe des comptes de trust
//
// Source: https://messervices.cyber.gouv.fr/documents-guides/anssi-guide-admin_securisee_si_ad_v1-0%20(3).pdf
//
// R42's own text (p.55) fixes no age threshold at all: "Les mots de passe
// des TDO sont renouvelés automatiquement tous les trente jours. Il convient
// néanmoins de régulièrement contrôler (chaque trimestre par exemple) qu'il
// n'existe pas de TDO échappant à cette règle" - it states the 30-day
// automatic-rotation period and a review CADENCE (quarterly), not an age
// LIMIT. The two thresholds below are a product choice, not an ANSSI number
// and not derived from the quarterly review cadence, which is a control
// frequency, not an age limit: Medium at 60 days (missed at least one
// 30-day cycle), High at 90 days (missed at least two).
const trustPasswordWarnDays = 60

// trustPasswordCriticalDays - see trustPasswordWarnDays above.
const trustPasswordCriticalDays = 90

type R42TrustPasswordOldDetector struct{ audit.BaseDetector }

func NewR42TrustPasswordOldDetector() *R42TrustPasswordOldDetector {
	return &R42TrustPasswordOldDetector{
		BaseDetector: audit.NewBaseDetector("ANSSI_R42_TRUST_PASSWORD_OLD", audit.CategoryCompliance),
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

func (d *R42TrustPasswordOldDetector) Detect(_ context.Context, data *audit.DetectorData) []types.Finding {
	if len(data.Trusts) == 0 {
		return nil
	}

	now := data.Now
	severity := types.SeverityMedium
	staleTrustDomains := map[string]bool{}
	var staleOrder []string
	var trustDetails []map[string]interface{}

	checkDirection := func(t types.Trust, direction string, exactDate time.Time, exactSource string) {
		date, source, ok := trustDirectionAge(exactDate, exactSource, t.WhenChanged)
		if !ok {
			return
		}
		age := now.Sub(date).Hours() / 24
		if age < trustPasswordWarnDays {
			return
		}
		if age >= trustPasswordCriticalDays {
			severity = types.SeverityHigh
		}
		if !staleTrustDomains[t.TargetDomain] {
			staleTrustDomains[t.TargetDomain] = true
			staleOrder = append(staleOrder, t.TargetDomain)
		}
		trustDetails = append(trustDetails, map[string]interface{}{
			"targetDomain": t.TargetDomain,
			"direction":    direction,
			"date":         date.UTC().Format(time.RFC3339),
			"source":       source,
			"ageDays":      int(age),
		})
	}

	for _, t := range data.Trusts {
		// MIT realms have no automatic rotation to control - the key is set
		// by hand (netdom /PasswordT, ksetup), so R42's "escapes automatic
		// rotation" framing does not apply to them.
		if t.TrustProtocolType == "MIT" {
			continue
		}
		hasOutgoing := t.TrustDirection == "Outbound" || t.TrustDirection == "Bidirectional"
		hasIncoming := t.TrustDirection == "Inbound" || t.TrustDirection == "Bidirectional"

		if hasOutgoing {
			checkDirection(t, "outgoing", t.OutgoingPasswordDate, t.OutgoingPasswordSource)
		}
		if hasIncoming {
			checkDirection(t, "incoming", t.IncomingPasswordDate, t.IncomingPasswordSource)
		}
	}

	if len(staleOrder) == 0 {
		return nil
	}

	var entities []types.AffectedEntity
	if data.IncludeDetails {
		for _, name := range staleOrder {
			entities = append(entities, types.AffectedEntity{
				Type: "trust",
				Name: name,
			})
		}
	}

	findings := wrapFindingWithRepro(d, "ANSSI R42 - Trust password not recently rotated",
		"ANSSI R42 (ANSSI-PA-099 p.55) requires regularly checking (quarterly, per ANSSI's own example cadence) that no trust escapes Windows' automatic 30-day secret rotation - R42 itself sets no age threshold, only the 30-day rotation period and a review cadence. "+
			fmt.Sprintf("%d trust(s) have gone at least %d days without renewing their secret in at least one direction, ", len(staleOrder), trustPasswordWarnDays)+
			"a product-chosen threshold (Medium at 60 days, High at 90 - not an ANSSI-specified age limit).",
		severity, len(staleOrder), entities,
		&types.FindingReproducibility{
			LDAPFilter: "(objectClass=trustedDomain)",
			LDAPAttrs:  []string{"name", "flatName", "whenChanged", "trustDirection", "trustType"},
			Notes: "Per direction (outgoing: trustAuthOutgoing, incoming: trustAuthIncoming), read the trust secret's real last-write date from msDS-ReplAttributeMetaData's ftimeLastOriginatingChange (a search rooted at the TDO itself, capped to one entry - not a base-scope read). If unreadable for the incoming direction, fall back to pwdLastSet of the <flatName>$ interdomain trust account (userAccountControl bit 0x800). If neither is available, the TDO's own whenChanged is only a lower-bound age (it can be newer than the secret itself) - never treat it as the rotation date.",
		})
	if data.IncludeDetails {
		findings[0].Details = map[string]interface{}{
			"trusts": trustDetails,
		}
	}
	return findings
}

func init() {
	audit.MustRegister(NewR42TrustPasswordOldDetector())
}
