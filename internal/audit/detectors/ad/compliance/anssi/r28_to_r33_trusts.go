package anssi

import (
	"context"
	"fmt"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// R28-R33 cover the trust hygiene block. Despite the filename, a full-text
// audit of ANSSI PA-099 found most of these IDs do NOT correspond to
// PA-099 recommendations R28-R33 - see each detector's own comment for the
// correct citation where one exists:
//   R28 - krbtgt password rotation cadence (PA-099 R41, p.54-55)
//   R29 - Trust SID filtering on outgoing extra-forest trusts (PA-099 R24, p.41)
//   R30 - Selective Authentication on outgoing extra-forest trusts (PA-099 R25+, p.42)
//   R31 - Kerberos delegation forbidden across incoming trusts (PA-099 R26, p.43; not directly measurable - see below)
//   R32 - Trust must use AES (no RC4 cross-realm) - unchanged, not audited here
//   R33 - Permissive external trust (PA-099 R24 primary + R25+ compensating fallback; R24's own text, not a single "R33")

// --- R28: krbtgt password rotation ---

type R28KrbtgtRotationDetector struct{ audit.BaseDetector }

func NewR28KrbtgtRotationDetector() *R28KrbtgtRotationDetector {
	return &R28KrbtgtRotationDetector{BaseDetector: audit.NewBaseDetector("ANSSI_R28_KRBTGT_NOT_ROTATED", audit.CategoryCompliance)}
}
func (d *R28KrbtgtRotationDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// krbtgt is the user whose objectSID ends with -502.
	//
	// ANSSI PA-099 R41 (p.53): "Le mot de passe du compte krbtgt doit être
	// renouvelé chaque année par les administrateurs" - once a year, not
	// every 180 days. The previous 180-day threshold was stricter than the
	// source and flagged Severity Critical on a state (180-365 days since
	// last rotation) ANSSI itself considers compliant.
	threshold := data.Now.AddDate(-1, 0, 0)
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
	desc := "ANSSI PA-099 R41 requires rotating the krbtgt account password at least once a year (\"renouvelé chaque année\", p.53)."
	if krbtgt != nil && !krbtgt.PasswordLastSet.IsZero() {
		days := int(data.Now.Sub(krbtgt.PasswordLastSet).Hours() / 24)
		desc = fmt.Sprintf("%s Last krbtgt password change: %d days ago.", desc, days)
	}
	// krbtgt is a single, always-known object; the finding previously
	// carried no AffectedEntities at all (motif(c): count fires, nothing
	// actionable for the client).
	var entities []types.AffectedEntity
	if count == 1 && data.IncludeDetails {
		entities = []types.AffectedEntity{types.UserToAffectedEntity(krbtgt)}
	}
	return wrapFinding(d, "ANSSI PA-099 R41 - krbtgt non roté (>1 an)", desc, types.SeverityCritical, count, entities)
}

// --- R29: Trust SID filtering enabled on every external/forest trust ---

type R29TrustSIDFilteringDetector struct{ audit.BaseDetector }

func NewR29TrustSIDFilteringDetector() *R29TrustSIDFilteringDetector {
	return &R29TrustSIDFilteringDetector{BaseDetector: audit.NewBaseDetector("ANSSI_R29_TRUST_SID_FILTERING_OFF", audit.CategoryCompliance)}
}
func (d *R29TrustSIDFilteringDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// ANSSI PA-099 (full-text source audit) R24 (p.41), "Durcir la
	// configuration des relations d'approbation AD sortantes extraforêt":
	// applies only to OUTGOING extra-forest trusts, and the mechanism
	// DIFFERS by trust type:
	//   - domain/external trust: harden by ADDING QUARANTINED_DOMAIN
	//     ("quarantine") - this is exactly types.Trust.SIDFiltering;
	//   - forest trust: harden by REMOVING TREAT_AS_EXTERNAL (SID history) -
	//     a different attribute the collector does not currently parse into
	//     types.Trust, so it cannot be checked here.
	// (The real R29 in PA-099 is unrelated: the general "reusable secrets
	// must not cross Tier boundaries" principle, p.46.) Scope is therefore
	// narrowed to what's both correct and measurable: outgoing external
	// (non-forest) trusts only.
	count := 0
	for _, t := range data.Trusts {
		if !strings.EqualFold(t.TrustType, "External") {
			continue
		}
		if !isOutgoing(t) {
			continue
		}
		if !t.SIDFiltering {
			count++
		}
	}
	return wrapFinding(d, "ANSSI PA-099 R24 - Trust externe sortant sans quarantaine (SID filtering)",
		"ANSSI PA-099 R24 (p.41) requires outgoing extra-forest DOMAIN (external) trusts to have the QUARANTINED_DOMAIN attribute (SID filtering / quarantine). KNOWN LIMITATION: R24's forest-trust hardening (removing TREAT_AS_EXTERNAL) is not checked here - that attribute is not currently collected - so forest trusts are excluded from this detector rather than checked against the wrong attribute.",
		types.SeverityHigh, count, nil)
}

// --- R30: Trust Selective Authentication ---

type R30TrustSelectiveAuthDetector struct{ audit.BaseDetector }

func NewR30TrustSelectiveAuthDetector() *R30TrustSelectiveAuthDetector {
	return &R30TrustSelectiveAuthDetector{BaseDetector: audit.NewBaseDetector("ANSSI_R30_TRUST_SELECTIVE_AUTH_OFF", audit.CategoryCompliance)}
}
func (d *R30TrustSelectiveAuthDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// ANSSI PA-099 (full-text source audit) R25+ (p.42), "Utiliser des
	// relations d'approbation sortantes avec authentification sélective":
	// applies to OUTGOING extra-forest trusts only ("relations d'approbation
	// SORTANTES extraforêt"), via the CROSS_ORGANIZATION attribute - exactly
	// types.Trust.SelectiveAuth. (The real R30/R30- in PA-099 is unrelated:
	// LAPS / local-admin-password rotation, p.47-48.) The previous version
	// never checked trust direction; an inbound-only trust is out of R25+'s
	// stated scope.
	count := 0
	for _, t := range data.Trusts {
		if isExternalOrForest(t) && isOutgoing(t) && !t.SelectiveAuth {
			count++
		}
	}
	return wrapFinding(d, "ANSSI PA-099 R25+ - Trust extraforêt sortant sans authentification sélective",
		"ANSSI PA-099 R25+ (p.42) recommends outgoing extra-forest trusts use Selective Authentication (CROSS_ORGANIZATION) so principals from the trusted domain can only authenticate to resources explicitly granted 'Allowed to authenticate'.",
		types.SeverityMedium, count, nil)
}

// --- R31: Trust TGT delegation forbidden cross-forest ---

type R31TrustTGTDelegationDetector struct{ audit.BaseDetector }

func NewR31TrustTGTDelegationDetector() *R31TrustTGTDelegationDetector {
	return &R31TrustTGTDelegationDetector{BaseDetector: audit.NewBaseDetector("ANSSI_R31_TRUST_TGT_DELEGATION", audit.CategoryCompliance)}
}
func (d *R31TrustTGTDelegationDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// ANSSI PA-099 (full-text source audit) R26 (p.43), "Interdire la
	// délégation Kerberos à travers les relations d'approbation entrantes":
	// applies to INCOMING trusts (not "across forest boundaries" broadly),
	// and the mechanism it names is the netdom /EnableTGTDelegation:No
	// switch. (The real R31 in PA-099 is unrelated: reusable secrets in
	// SYSVOL scripts/GPP, p.49.) The bit values 0x200/0x800 and the
	// "TRUST_ATTRIBUTE_DISABLE_AUTH_TARGET_VALIDATION" name previously cited
	// here do not appear anywhere in PA-099 and are unverifiable against it.
	//
	// KNOWN LIMITATION: EnableTGTDelegation is not currently collected by
	// the LDAP trust parser, so R26 compliance cannot be directly measured.
	// This detector is now at least scoped to the right trust direction
	// (incoming), using SelectiveAuth as a heuristic proxy - it is NOT
	// equivalent to EnableTGTDelegation and should be treated as "not
	// verified", not as a confirmed R26 reading.
	count := 0
	for _, t := range data.Trusts {
		if !isIncoming(t) {
			continue
		}
		if !t.SelectiveAuth {
			count++
		}
	}
	return wrapFinding(d, "ANSSI PA-099 R26 - Trust entrant potentiellement permissif à la délégation Kerberos (non vérifié)",
		"ANSSI PA-099 R26 (p.43) requires incoming trusts to have Kerberos delegation disabled (EnableTGTDelegation:No). KNOWN LIMITATION: EnableTGTDelegation is not currently collected - this finding uses Selective Authentication as an imperfect proxy on incoming trusts and does not directly verify R26 compliance; treat as \"not verified\", not as a confirmed violation.",
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
	return wrapFinding(d, "ANSSI R32 - Trust autorisant RC4 (pas AES-only)",
		"ANSSI R32 requires AES-only on trust referrals (msDS-SupportedEncryptionTypes flag). RC4 cross-realm tickets are kerberoastable and downgrade attacks remain possible.",
		types.SeverityMedium, count, nil)
}

// --- R33: No permissive external trust ---

type R33ExternalTrustPermissiveDetector struct{ audit.BaseDetector }

func NewR33ExternalTrustPermissiveDetector() *R33ExternalTrustPermissiveDetector {
	return &R33ExternalTrustPermissiveDetector{BaseDetector: audit.NewBaseDetector("ANSSI_R33_EXTERNAL_TRUST_PERMISSIVE", audit.CategoryCompliance)}
}
func (d *R33ExternalTrustPermissiveDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// ANSSI PA-099 (full-text source audit): no single R-number states an
	// "external trust is permissive if EITHER control is missing" rule. The
	// real R33 is unrelated (scheduled-task/service-account secrets,
	// p.50-51). The two relevant controls are R24 (p.41, SID
	// filtering/quarantine - the primary hardening for outgoing extra-forest
	// domain trusts) and R25+ (p.42, Selective Authentication) - and R24's
	// own text frames R25+ as a compensating FALLBACK to apply "à défaut"
	// (failing) full R24 compliance, not as an independently-required
	// second layer: "À défaut, appliquer la recommandation R25+ permet
	// d'atténuer le risque de sécurité que représente un filtrage
	// insuffisant". So either control present is an acceptable mitigation;
	// the previous OR-trigger (flag if EITHER is missing, i.e. require BOTH
	// to be compliant) was stricter than the source. Scope narrowed to
	// outgoing trusts per R24/R25+'s own "sortantes" wording.
	count := 0
	for _, t := range data.Trusts {
		if !strings.EqualFold(t.TrustType, "External") {
			continue
		}
		if !isOutgoing(t) {
			continue
		}
		if !t.SelectiveAuth && !t.SIDFiltering {
			count++
		}
	}
	return wrapFinding(d, "ANSSI PA-099 R24/R25+ - Trust externe sortant sans aucune protection (ni quarantaine, ni authentification sélective)",
		"An outgoing external trust is permissive when it has NEITHER of ANSSI PA-099's two mitigations for extra-forest trust risk: R24's quarantine/SID filtering (p.41, primary) or R25+'s Selective Authentication (p.42, compensating fallback \"à défaut\" of R24). Per R24's own text, either one present is an acceptable mitigation.",
		types.SeverityHigh, count, nil)
}

// --- Shared ---

func isExternalOrForest(t types.Trust) bool {
	tt := strings.ToLower(t.TrustType)
	return tt == "external" || tt == "forest"
}

// isOutgoing reports whether t has an outgoing leg - i.e. Outbound or
// Bidirectional. PA-099's trust-hardening recommendations (R24, R25+) are
// explicitly scoped to "relations d'approbation sortantes" (outgoing
// trusts); a purely Inbound trust is out of their stated scope.
func isOutgoing(t types.Trust) bool {
	switch strings.ToLower(t.TrustDirection) {
	case "outbound", "bidirectional":
		return true
	default:
		return false
	}
}

// isIncoming reports whether t has an incoming leg - i.e. Inbound or
// Bidirectional. PA-099 R26 ("Interdire la délégation Kerberos à travers
// les relations d'approbation entrantes") is scoped to incoming trusts.
func isIncoming(t types.Trust) bool {
	switch strings.ToLower(t.TrustDirection) {
	case "inbound", "bidirectional":
		return true
	default:
		return false
	}
}

func init() {
	audit.MustRegister(NewR28KrbtgtRotationDetector())
	audit.MustRegister(NewR29TrustSIDFilteringDetector())
	audit.MustRegister(NewR30TrustSelectiveAuthDetector())
	audit.MustRegister(NewR31TrustTGTDelegationDetector())
	audit.MustRegister(NewR32TrustRC4Detector())
	audit.MustRegister(NewR33ExternalTrustPermissiveDetector())
}
