package anssi

import (
	"context"
	"fmt"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// Sub-recommendations of ANSSI PA-022 (R2.1, R2.2, R3.1, R12.1, R12.2, R15.1,
// R15.2, R20.1, R20.2, R29.1, R34.1, R34.2, R36.1). These are the
// fine-grained checks behind the main R-codes that auditors PASSI typically
// drill into during qualification audits.

// v3.1.21 dedup - ANSSI_R2_1_BUILTIN_ADMIN_NOT_RENAMED removed (same check
// as M12_DEFAULT_ADMIN_NOT_RENAMED). Mapping migrated (M12 now maps to
// both GP-042 M12 and PA-099 R44).

// --- R2.2: Guest account enabled ---

type R22GuestEnabledDetector struct{ audit.BaseDetector }

func NewR22GuestEnabledDetector() *R22GuestEnabledDetector {
	return &R22GuestEnabledDetector{BaseDetector: audit.NewBaseDetector("ANSSI_R2_2_GUEST_ENABLED", audit.CategoryCompliance)}
}
func (d *R22GuestEnabledDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	count := 0
	for _, u := range data.Users {
		if strings.HasSuffix(u.ObjectSID, "-501") && !u.Disabled {
			count = 1
			break
		}
	}
	return wrapFinding(d, "ANSSI R2.2 - Compte Guest activé",
		"ANSSI R2.2 (sub-reco) requires the built-in Guest account (RID 501) to be permanently disabled.",
		types.SeverityHigh, count, nil)
}

// v3.1.21 dedup - ANSSI_R3_1_SMARTCARD_NOT_REQUIRED removed (same UAC bit
// check as ADMIN_NO_SMARTCARD). Mapping migrated.

// Access-mask bits that turn an ACE on a property set or an extended right
// into an actual privilege grant. Reading a property is not a
// privilege: R12.2 used to match on the property-set GUID alone, which made
// every `BUILTIN\Pre-Windows 2000 Compatible Access` READ_PROP ACE - the one
// AD places on every user object at domain install - a HIGH finding.
const (
	adsRightDSWriteProp     = 0x00000020 // ADS_RIGHT_DS_WRITE_PROP
	adsRightDSControlAccess = 0x00000100 // ADS_RIGHT_DS_CONTROL_ACCESS (exercises an extended right)
	adsRightGenericWrite    = 0x40000000
	adsRightGenericAll      = 0x10000000
)

// aclEntities projects matching ACEs onto aclEntry entities so every ANSSI ACL
// finding is actionable (trustee + right + target). Callers pass only the ACEs
// they counted, so Count == len(entities).
func aclEntities(data *audit.DetectorData, matched []types.ACLEntry) []types.AffectedEntity {
	if !data.IncludeDetails {
		return nil
	}
	out := make([]types.AffectedEntity, 0, len(matched))
	for _, ace := range matched {
		if ent := audit.ACLEntryToAffectedEntity(ace, data.ObjectByDN, data.ObjectBySID); ent.Type != "" {
			out = append(out, ent)
			continue
		}
		out = append(out, data.EntityForDN(ace.ObjectDN))
	}
	return out
}

// --- R12.1: User-Force-Change-Password ACL on privileged accounts ---

type R121ForcePwdResetDetector struct{ audit.BaseDetector }

func NewR121ForcePwdResetDetector() *R121ForcePwdResetDetector {
	return &R121ForcePwdResetDetector{BaseDetector: audit.NewBaseDetector("ANSSI_R12_1_FORCE_PWD_RESET_PRIVS", audit.CategoryCompliance)}
}
func (d *R121ForcePwdResetDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// Extended-right GUID for User-Force-Change-Password
	const forceChangePwdGUID = "00299570-246d-11d0-a768-00aa006e0529"
	var matched []types.ACLEntry
	for _, ace := range data.ACLEntries {
		if !strings.EqualFold(ace.ObjectType, forceChangePwdGUID) {
			continue
		}
		// An extended right is exercised through CONTROL_ACCESS, not
		// WRITE_PROP - full control (0xF01FF) carries it too. Requiring a
		// write bit here would be a false negative on the very delegation
		// this check exists to find.
		if ace.AccessMask&(adsRightDSControlAccess|adsRightGenericAll) == 0 {
			continue
		}
		if isWellKnownAdminTrustee(ace.Trustee) {
			continue
		}
		matched = append(matched, ace)
	}
	return wrapFinding(d, "ANSSI R12.1 - User-Force-Change-Password accordé hors comptes système",
		"ANSSI R12.1 (sub-reco) - the extended right User-Force-Change-Password lets the holder reset arbitrary user passwords without knowing the old one. Should be restricted to Tier 0 admin groups only.",
		types.SeverityHigh, len(matched), aclEntities(data, matched))
}

// --- R12.2: User-Account-Restrictions ACL ---

type R122UserRestrictionsDetector struct{ audit.BaseDetector }

func NewR122UserRestrictionsDetector() *R122UserRestrictionsDetector {
	return &R122UserRestrictionsDetector{BaseDetector: audit.NewBaseDetector("ANSSI_R12_2_USER_RESTRICTIONS_PRIVS", audit.CategoryCompliance)}
}
func (d *R122UserRestrictionsDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// Property-set GUID for User-Account-Restrictions
	const userRestrictionsGUID = "4c164200-20c0-11d0-a768-00aa006e0529"
	var matched []types.ACLEntry
	for _, ace := range data.ACLEntries {
		if !strings.EqualFold(ace.ObjectType, userRestrictionsGUID) {
			continue
		}
		// The check is about the ability to MODIFY userAccountControl. A
		// READ_PROP ACE on the property set conveys no privilege at all.
		if ace.AccessMask&(adsRightDSWriteProp|adsRightGenericWrite|adsRightGenericAll) == 0 {
			continue
		}
		if isWellKnownAdminTrustee(ace.Trustee) {
			continue
		}
		matched = append(matched, ace)
	}
	return wrapFinding(d, "ANSSI R12.2 - User-Account-Restrictions accordé hors comptes système",
		"ANSSI R12.2 (sub-reco) - the User-Account-Restrictions property set lets the holder modify userAccountControl bits (disable, no-preauth, smartcard required, etc.). Should be restricted to Tier 0 admins only.",
		types.SeverityHigh, len(matched), aclEntities(data, matched))
}

// --- R56/R57: RODC deployed - Tier 0 groups missing from the deny-replication list ---
//
// "R15.1" never existed as PA-099 sub-reco numbering (see R36.1 note above -
// PA-099 has no dotted sub-recommendation numbering at all). mappings.go
// already tags this detector ID against the real controls: R56 (p.71,
// "Déployer des RODC lorsque la sécurité physique n'est pas assurée") and
// R57 (p.72, "Appliquer les recommandations de sécurisation des RODC").
//
// The previous implementation flagged an EMPTY "Allowed RODC Password
// Replication Group" as non-compliant. That is backwards: R57's actual text
// says only site-local Tier 2 accounts should ever appear in that allow
// list, and an empty allow list is the safe default (nothing is cached) -
// not a violation of anything R56/R57 say. What R57 DOES require, textually
// (first bullet, p.72): "tous les comptes et groupes du Tier 0 ... doivent
// figurer dans la liste des comptes qui ne sont pas autorisés à être
// répliqués" - i.e. Tier 0 groups must explicitly appear in the deny list
// (msDS-NeverRevealGroup, default-populated via the builtin "Denied RODC
// Password Replication Group"). That's what this detector now checks. It is
// complementary to, not a duplicate of, ANSSI_R15_2_T0_ADMIN_REPLICATED_TO_RODC
// below (which checks the allow list) and of the empirical
// RODC_PRIVILEGED_CACHING detector (which checks msDS-RevealedList, i.e.
// credentials already exposed in practice).

type R151RODCNoAllowedReplDetector struct{ audit.BaseDetector }

func NewR151RODCNoAllowedReplDetector() *R151RODCNoAllowedReplDetector {
	return &R151RODCNoAllowedReplDetector{BaseDetector: audit.NewBaseDetector("ANSSI_R15_1_RODC_NO_ALLOWED_REPL", audit.CategoryCompliance)}
}

// tier0DeniedGroupNames are the built-in Tier 0 groups R57 (p.72) requires
// to appear in the RODC deny-replication list.
var tier0DeniedGroupNames = []string{"domain admins", "enterprise admins", "schema admins"}

func (d *R151RODCNoAllowedReplDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// Only emit if at least one RODC exists in the domain.
	hasRODC := false
	for _, c := range data.Computers {
		if c.IsRODC {
			hasRODC = true
			break
		}
	}
	if !hasRODC {
		return wrapFinding(d, "ANSSI R56/R57 - N/A (pas de RODC déployé)",
			"ANSSI R56/R57 only apply when at least one RODC is present in the domain. None detected.",
			types.SeverityInfo, 0, nil)
	}

	denyMembers := map[string]bool{}
	for _, g := range data.Groups {
		if strings.EqualFold(g.SAMAccountName, "Denied RODC Password Replication Group") {
			for _, m := range g.Members {
				denyMembers[strings.ToLower(m)] = true
			}
		}
	}
	var missing []string
	for _, t0name := range tier0DeniedGroupNames {
		found := false
		for m := range denyMembers {
			if strings.Contains(m, t0name) {
				found = true
				break
			}
		}
		if !found {
			missing = append(missing, t0name)
		}
	}

	if len(missing) == 0 {
		return wrapFinding(d, "ANSSI R56/R57 - Groupes Tier 0 présents dans la liste de refus de réplication RODC",
			"ANSSI R57 (p.72) requires every Tier 0 account/group to appear in the RODC deny-replication list. Domain Admins, Enterprise Admins and Schema Admins are all present.",
			types.SeverityMedium, 0, nil)
	}
	return wrapFinding(d, "ANSSI R56/R57 - Groupe(s) Tier 0 absents de la liste de refus de réplication RODC",
		"ANSSI R57 (p.72) requires every Tier 0 account/group to appear in the RODC deny-replication list (msDS-NeverRevealGroup, default-populated via the builtin 'Denied RODC Password Replication Group'), as defense-in-depth against a Tier 0 credential ever being cached on a physically-exposed RODC. "+
			fmt.Sprintf("Missing from that deny list: %s.", strings.Join(missing, ", ")),
		types.SeverityMedium, len(missing), nil)
}

// --- R57: T0 admins must NOT be in the RODC allow-replication list ---

type R152T0AdminInRODCDetector struct{ audit.BaseDetector }

func NewR152T0AdminInRODCDetector() *R152T0AdminInRODCDetector {
	return &R152T0AdminInRODCDetector{BaseDetector: audit.NewBaseDetector("ANSSI_R15_2_T0_ADMIN_REPLICATED_TO_RODC", audit.CategoryCompliance)}
}
func (d *R152T0AdminInRODCDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// Build T0 DN set (Domain Admins, Enterprise Admins, Schema Admins members).
	t0 := map[string]bool{}
	for _, g := range data.Groups {
		sam := strings.ToLower(g.SAMAccountName)
		if sam == "domain admins" || sam == "enterprise admins" || sam == "schema admins" {
			for _, m := range g.Members {
				t0[strings.ToLower(m)] = true
			}
		}
	}
	count := 0
	for _, g := range data.Groups {
		if !strings.EqualFold(g.SAMAccountName, "Allowed RODC Password Replication Group") {
			continue
		}
		for _, m := range g.Members {
			if t0[strings.ToLower(m)] {
				count++
			}
		}
	}
	return wrapFinding(d, "ANSSI R57 - Admins T0 présents dans 'Allowed RODC Password Replication Group'",
		"ANSSI R57 (p.72) - Tier 0 administrators (Domain/Enterprise/Schema Admins) MUST NEVER be in the Allowed RODC Password Replication Group. Their hash on a physically-exposed RODC = instant golden ticket on RODC theft. (\"R15.2\" is a legacy internal label - PA-099 has no dotted sub-recommendation numbering; mappings.go already tags this ID against the real control, R57.)",
		types.SeverityCritical, count, nil)
}

// v3.1.21 dedup - ANSSI_R20_1_BACKUP_OPERATORS_MEMBER and
// ANSSI_R20_2_PRINT_OPERATORS_MEMBER removed (same group memberships as
// custom BACKUP_OPERATORS_MEMBER / PRINT_OPERATORS_MEMBER). Mappings
// preserved (custom IDs already mapped to PA-099 R23 in mappings.go).

// --- R25+: Outgoing forest trust without selective auth ---
//
// "R29.1" never existed (PA-099 has no dotted sub-recommendation numbering).
// mappings.go already tags this ID against the real control, R25+ (p.41-42,
// "Utiliser des relations d'approbation sortantes avec authentification
// sélective"). R25+'s text is explicitly scoped to OUTGOING ("sortantes")
// extra-forest trusts - an inbound-only forest trust has no "sortante"
// component and is out of R25+'s scope. The previous implementation counted
// every non-selective-auth forest trust regardless of direction, which
// would flag an inbound-only trust for a control that doesn't apply to it.

type R291ForestTrustNoSelAuthDetector struct{ audit.BaseDetector }

func NewR291ForestTrustNoSelAuthDetector() *R291ForestTrustNoSelAuthDetector {
	return &R291ForestTrustNoSelAuthDetector{BaseDetector: audit.NewBaseDetector("ANSSI_R29_1_FOREST_TRUST_NO_SELECTIVE_AUTH", audit.CategoryCompliance)}
}

// hasOutboundComponent reports whether a trust carries an outgoing
// authentication path - Outbound or Bidirectional. Inbound-only trusts have
// no outbound leg and are out of R25+'s scope.
func hasOutboundComponent(t types.Trust) bool {
	if t.TrustDirectionInt == 2 || t.TrustDirectionInt == 3 {
		return true
	}
	return strings.EqualFold(t.TrustDirection, "Outbound") || strings.EqualFold(t.TrustDirection, "Bidirectional")
}

func (d *R291ForestTrustNoSelAuthDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	count := 0
	for _, t := range data.Trusts {
		if !strings.EqualFold(t.TrustType, "Forest") {
			continue
		}
		if !hasOutboundComponent(t) {
			continue // R25+ scopes outgoing trusts only
		}
		if !t.SelectiveAuth {
			count++
		}
	}
	return wrapFinding(d, "ANSSI R25+ - Trust forêt sortant sans Selective Authentication",
		"ANSSI R25+ (p.41-42) requires outgoing extra-forest trusts to use Selective Authentication. Scoped to trusts with an outbound component (Outbound or Bidirectional); an inbound-only forest trust has no outbound leg and is out of R25+'s scope.",
		types.SeverityMedium, count, nil)
}

// v3.1.21 dedup - ANSSI_R34_1_CACHED_LOGONS_TOO_HIGH removed. Custom
// CACHED_LOGONS_EXCESSIVE absorbed the ANSSI threshold (>4 instead of >2)
// for compliance with the official PA-099 sub-reco. Mapping migrated.

// --- R34.2: RestrictRemoteSAM ---

type R342RestrictRemoteSAMDetector struct{ audit.BaseDetector }

func NewR342RestrictRemoteSAMDetector() *R342RestrictRemoteSAMDetector {
	return &R342RestrictRemoteSAMDetector{BaseDetector: audit.NewBaseDetector("ANSSI_R34_2_RESTRICT_REMOTE_SAM_OFF", audit.CategoryCompliance)}
}
func (d *R342RestrictRemoteSAMDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	configured := false
	for _, p := range data.GPOPolicies {
		if p == nil || p.RegistrySettings == nil || p.RegistrySettings.RestrictRemoteSAM == nil {
			continue
		}
		if *p.RegistrySettings.RestrictRemoteSAM != "" {
			configured = true
			break
		}
	}
	count := 0
	if !configured {
		count = 1
	}
	return wrapFinding(d, "ANSSI R34.2 - RestrictRemoteSAM non configuré",
		"ANSSI R34.2 (sub-reco) - SAM\\RestrictRemoteSam must be set to a SDDL allowing only admins. Without it, any domain user can enumerate local accounts via SAMR (Mimikatz / netsesh).",
		types.SeverityMedium, count, nil)
}

// --- LAPS password expiry too long ---
//
// "R36.1" never existed: PA-099 has no dotted sub-recommendation
// numbering at all (verified: zero "R\d+\.\d+" matches anywhere in the
// published v1.0 PDF), and R36 itself is "Traiter les risques inhérents aux
// IGC qui pèsent sur le Tier 0" (CA/PKI risk, unrelated to LAPS). The real
// LAPS recommendation is R30 ("Diversifier et renouveler automatiquement les
// mots de passe des comptes admin locaux", p.48): it requires deploying an
// automatic local-admin-password rotation solution (LAPS or equivalent) but
// - checked against the full body text of R30 - specifies NO numeric
// rotation-interval threshold. mappings.go already tags this detector ID
// against PA-099 R30, not R36.
//
// 30 days is the well-known default PasswordAgeDays of legacy Microsoft
// LAPS, not an ANSSI-mandated number: it's used here as an etc-collector
// product benchmark for "rotation interval too long", same category as
// daCountBenchmark in r2-privileged-accounts.go.
//
// v3.1.19 - REWRITE: real check based on Computer.LAPSPasswordExpiry,
// populated from ms-Mcs-AdmPwdExpirationTime (legacy) or
// msLAPS-PasswordExpirationTime (modern Windows LAPS).

type R361LAPSExpiryDetector struct{ audit.BaseDetector }

func NewR361LAPSExpiryDetector() *R361LAPSExpiryDetector {
	return &R361LAPSExpiryDetector{BaseDetector: audit.NewBaseDetector("ANSSI_R36_1_LAPS_EXPIRY_TOO_LONG", audit.CategoryCompliance)}
}

// lapsMaxExpiryDaysBenchmark is the legacy Microsoft LAPS default
// PasswordAgeDays, used as an etc-collector product benchmark - PA-099 R30
// requires automatic local-admin-password rotation but specifies no
// numeric interval.
const lapsMaxExpiryDaysBenchmark = 30

func (d *R361LAPSExpiryDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	threshold := data.Now.AddDate(0, 0, lapsMaxExpiryDaysBenchmark)
	var stale []types.Computer
	for _, c := range data.Computers {
		if c.LAPSPasswordExpiry.IsZero() {
			continue // computer outside LAPS scope - not in scope of this check
		}
		if c.LAPSPasswordExpiry.After(threshold) {
			stale = append(stale, c)
		}
	}
	if len(stale) == 0 {
		return nil
	}
	return wrapFinding(d, "LAPS password expiry beyond product benchmark (30 days)",
		fmt.Sprintf("ANSSI PA-099 R30 requires an automatic local-admin-password rotation solution (LAPS or equivalent) but specifies no rotation-interval number. %d computer(s) currently have a LAPS expiry timestamp more than %d days in the future - beyond the legacy LAPS default and etc-collector's product benchmark for 'rotation interval too long'. Reduce the LAPS GPO PasswordAgeDays to %d (or lower).", len(stale), lapsMaxExpiryDaysBenchmark, lapsMaxExpiryDaysBenchmark),
		types.SeverityMedium, len(stale), computersToEntities(stale, data.IncludeDetails))
}

func init() {
	audit.MustRegister(NewR22GuestEnabledDetector())
	audit.MustRegister(NewR121ForcePwdResetDetector())
	audit.MustRegister(NewR122UserRestrictionsDetector())
	audit.MustRegister(NewR151RODCNoAllowedReplDetector())
	audit.MustRegister(NewR152T0AdminInRODCDetector())
	audit.MustRegister(NewR291ForestTrustNoSelAuthDetector())
	audit.MustRegister(NewR342RestrictRemoteSAMDetector())
	audit.MustRegister(NewR361LAPSExpiryDetector())
}
