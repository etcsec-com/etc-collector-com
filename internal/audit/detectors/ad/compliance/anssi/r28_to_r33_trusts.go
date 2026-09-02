package anssi

import (
	"context"
	"fmt"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// R28-R33 cover the trust hygiene block of ANSSI PA-022:
//   R28 — krbtgt password rotation cadence
//   R29 — Trust SID filtering enabled
//   R30 — Trust Selective Authentication
//   R31 — Trust TGT delegation forbidden across forest boundaries
//   R32 — Trust must use AES (no RC4 cross-realm)
//   R33 — No permissive external trust

// --- R28: krbtgt password rotation ---

type R28KrbtgtRotationDetector struct{ audit.BaseDetector }

func NewR28KrbtgtRotationDetector() *R28KrbtgtRotationDetector {
	return &R28KrbtgtRotationDetector{BaseDetector: audit.NewBaseDetector("ANSSI_R28_KRBTGT_NOT_ROTATED", audit.CategoryCompliance)}
}
func (d *R28KrbtgtRotationDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// krbtgt is the user whose objectSID ends with -502.
	threshold := data.Now.AddDate(0, 0, -180)
	var krbtgt *types.User
	for i := range data.Users {
		u := &data.Users[i]
		if strings.HasSuffix(u.ObjectSID, "-502") || strings.EqualFold(u.SAMAccountName, "krbtgt") {
			krbtgt = u
			break
		}
	}
	count := 0
	if krbtgt != nil && !krbtgt.PasswordLastSet.IsZero() && krbtgt.PasswordLastSet.Before(threshold) {
		count = 1
	}
	desc := "ANSSI R28 requires rotating the krbtgt account password at least every 180 days (twice in a row to invalidate stale TGTs / Golden Ticket scenarios)."
	if krbtgt != nil && !krbtgt.PasswordLastSet.IsZero() {
		days := int(data.Now.Sub(krbtgt.PasswordLastSet).Hours() / 24)
		desc = fmt.Sprintf("%s Last krbtgt password change: %d days ago.", desc, days)
	}
	// T_129 — krbtgt is a single, always-known object; the finding previously
	// carried no AffectedEntities at all (motif(c): count fires, nothing
	// actionable for the client).
	var entities []types.AffectedEntity
	if count == 1 && data.IncludeDetails {
		entities = []types.AffectedEntity{types.UserToAffectedEntity(krbtgt)}
	}
	return wrapFinding(d, "ANSSI R28 — krbtgt non roté (>180j)", desc, types.SeverityCritical, count, entities)
}

// --- R29: Trust SID filtering enabled on every external/forest trust ---

type R29TrustSIDFilteringDetector struct{ audit.BaseDetector }

func NewR29TrustSIDFilteringDetector() *R29TrustSIDFilteringDetector {
	return &R29TrustSIDFilteringDetector{BaseDetector: audit.NewBaseDetector("ANSSI_R29_TRUST_SID_FILTERING_OFF", audit.CategoryCompliance)}
}
func (d *R29TrustSIDFilteringDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	count := 0
	for _, t := range data.Trusts {
		if isExternalOrForest(t) && !t.SIDFiltering {
			count++
		}
	}
	return wrapFinding(d, "ANSSI R29 — Trust externe/forêt sans SID filtering",
		"ANSSI R29 requires SID filtering (TRUST_ATTRIBUTE_QUARANTINED_DOMAIN) on every external or forest trust to prevent cross-domain SID injection escalation.",
		types.SeverityHigh, count, nil)
}

// --- R30: Trust Selective Authentication ---

type R30TrustSelectiveAuthDetector struct{ audit.BaseDetector }

func NewR30TrustSelectiveAuthDetector() *R30TrustSelectiveAuthDetector {
	return &R30TrustSelectiveAuthDetector{BaseDetector: audit.NewBaseDetector("ANSSI_R30_TRUST_SELECTIVE_AUTH_OFF", audit.CategoryCompliance)}
}
func (d *R30TrustSelectiveAuthDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	count := 0
	for _, t := range data.Trusts {
		if isExternalOrForest(t) && !t.SelectiveAuth {
			count++
		}
	}
	return wrapFinding(d, "ANSSI R30 — Trust externe/forêt sans Selective Authentication",
		"ANSSI R30 requires Selective Authentication on cross-organization trusts so principals from the partner domain can only access resources where they're explicitly granted 'Allowed to authenticate'.",
		types.SeverityMedium, count, nil)
}

// --- R31: Trust TGT delegation forbidden cross-forest ---

type R31TrustTGTDelegationDetector struct{ audit.BaseDetector }

func NewR31TrustTGTDelegationDetector() *R31TrustTGTDelegationDetector {
	return &R31TrustTGTDelegationDetector{BaseDetector: audit.NewBaseDetector("ANSSI_R31_TRUST_TGT_DELEGATION", audit.CategoryCompliance)}
}
func (d *R31TrustTGTDelegationDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// Without exposing the raw trustAttributes int we can only signal: any
	// forest trust without selective auth + AES = candidate for unconstrained
	// TGT delegation across the boundary. Conservative emit: report any
	// forest trust without selective auth as TGT-delegation risk (heuristic).
	count := 0
	for _, t := range data.Trusts {
		if strings.EqualFold(t.TrustType, "Forest") && !t.SelectiveAuth {
			count++
		}
	}
	return wrapFinding(d, "ANSSI R31 — Trust forêt potentiellement permissif au TGT delegation",
		"ANSSI R31 forbids TGT delegation across forest boundaries (TRUST_ATTRIBUTE_DISABLE_AUTH_TARGET_VALIDATION). Without selective auth, a forest trust enables TGT relay in many setups.",
		types.SeverityHigh, count, nil)
}

// --- R32: Trust must support AES (no RC4 cross-realm) ---

type R32TrustRC4Detector struct{ audit.BaseDetector }

func NewR32TrustRC4Detector() *R32TrustRC4Detector {
	return &R32TrustRC4Detector{BaseDetector: audit.NewBaseDetector("ANSSI_R32_TRUST_RC4_ALLOWED", audit.CategoryCompliance)}
}
func (d *R32TrustRC4Detector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	count := 0
	for _, t := range data.Trusts {
		// AES not enabled OR RC4 explicitly enabled = downgrade risk.
		if !t.AESEnabled || t.RC4Enabled {
			count++
		}
	}
	return wrapFinding(d, "ANSSI R32 — Trust autorisant RC4 (pas AES-only)",
		"ANSSI R32 requires AES-only on trust referrals (msDS-SupportedEncryptionTypes flag). RC4 cross-realm tickets are kerberoastable and downgrade attacks remain possible.",
		types.SeverityMedium, count, nil)
}

// --- R33: No permissive external trust ---

type R33ExternalTrustPermissiveDetector struct{ audit.BaseDetector }

func NewR33ExternalTrustPermissiveDetector() *R33ExternalTrustPermissiveDetector {
	return &R33ExternalTrustPermissiveDetector{BaseDetector: audit.NewBaseDetector("ANSSI_R33_EXTERNAL_TRUST_PERMISSIVE", audit.CategoryCompliance)}
}
func (d *R33ExternalTrustPermissiveDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// External (non-forest) trust + no selective auth + no SID filtering = permissive.
	count := 0
	for _, t := range data.Trusts {
		if !strings.EqualFold(t.TrustType, "External") {
			continue
		}
		if !t.SelectiveAuth || !t.SIDFiltering {
			count++
		}
	}
	return wrapFinding(d, "ANSSI R33 — Trust externe permissif (pas de selective auth + pas de SID filtering)",
		"ANSSI R33 forbids permissive external trusts. An external trust without selective auth AND without SID filtering opens cross-domain privilege paths and SID injection.",
		types.SeverityHigh, count, nil)
}

// --- Shared ---

func isExternalOrForest(t types.Trust) bool {
	tt := strings.ToLower(t.TrustType)
	return tt == "external" || tt == "forest"
}

func init() {
	audit.MustRegister(NewR28KrbtgtRotationDetector())
	audit.MustRegister(NewR29TrustSIDFilteringDetector())
	audit.MustRegister(NewR30TrustSelectiveAuthDetector())
	audit.MustRegister(NewR31TrustTGTDelegationDetector())
	audit.MustRegister(NewR32TrustRC4Detector())
	audit.MustRegister(NewR33ExternalTrustPermissiveDetector())
}
