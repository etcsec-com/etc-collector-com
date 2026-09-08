package anssi

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// ANSSI-PA-099 R15, R19+, R40 - Tier 0 baseline hardening detectors.
//
// All three are auditable from LDAP only:
//   R15  - Augmenter les niveaux fonctionnels des domaines et des forêts AD
//   R19+ - Utiliser Windows en « Server Core » sur le périmètre du Tier 0
//   R40  - Appliquer des stratégies de mot de passe affinées (FGPP/PSO) pour
//          les comptes du Tier 0
//
// Source: https://messervices.cyber.gouv.fr/documents-guides/anssi-guide-admin_securisee_si_ad_v1-0%20(3).pdf

// --- R15: domain/forest functional level below ANSSI baseline ---

// minFunctionalLevel is the lowest msDS-Behavior-Version value R15 (p.33)
// itself names as its floor: "Le niveau de fonctionnalité 6 (Windows
// Serveur 2012R2) est le minimum requis pour mettre en œuvre les
// recommandations de ce guide." Level 7 (Windows Server 2016) unlocks
// further benefits the guide separately describes (smart card account
// security improvements, PIM/PAM forest trusts) but R15's own text sets
// the required floor at 6, not 7 - the previous value here (7) was
// stricter than the source and would flag a 2012R2-level domain, which R15
// itself calls sufficient, as non-compliant.
const minFunctionalLevel = 6 // Windows Server 2012 R2

type R15FunctionalLevelDetector struct{ audit.BaseDetector }

func NewR15FunctionalLevelDetector() *R15FunctionalLevelDetector {
	return &R15FunctionalLevelDetector{
		BaseDetector: audit.NewBaseDetector("ANSSI_R15_LOW_FUNCTIONAL_LEVEL", audit.CategoryCompliance),
	}
}

func (d *R15FunctionalLevelDetector) Detect(_ context.Context, data *audit.DetectorData) []types.Finding {
	if data.DomainInfo == nil {
		return nil
	}
	di := data.DomainInfo

	domLow := di.FunctionalLevelInt > 0 && di.FunctionalLevelInt < minFunctionalLevel
	forestLow := di.ForestFunctionalLevelInt > 0 && di.ForestFunctionalLevelInt < minFunctionalLevel
	if !domLow && !forestLow {
		return nil
	}

	parts := []string{}
	if domLow {
		parts = append(parts, fmt.Sprintf("domain functional level = %d (%s)", di.FunctionalLevelInt, di.FunctionalLevel))
	}
	if forestLow {
		parts = append(parts, fmt.Sprintf("forest functional level = %d (%s)", di.ForestFunctionalLevelInt, di.ForestFunctionalLevel))
	}

	return wrapFindingWithRepro(d, "ANSSI R15 - AD functional level below required baseline",
		"ANSSI R15 (p.33) states Windows Server 2012 R2 (msDS-Behavior-Version=6) is the minimum functional level required to implement the guide's recommendations; higher levels (e.g. 7 / Windows Server 2016) unlock further benefits (smart card account security, PIM/PAM forest trusts) but are not R15's floor. Current state: "+strings.Join(parts, "; ")+".",
		types.SeverityHigh, 1, nil,
		&types.FindingReproducibility{
			LDAPBaseDN: di.DomainDN,
			LDAPFilter: "(objectClass=domain)",
			LDAPAttrs:  []string{"msDS-Behavior-Version"},
			Notes:      "Compare msDS-Behavior-Version on the domain root and on CN=Partitions,CN=Configuration. Both must be ≥ 7 (Windows Server 2016).",
		})
}

// --- R19+: Server Core usage on Tier 0 DCs cannot be confirmed via LDAP ---
//
// The previous implementation flagged any DC whose LDAP operatingSystem
// string didn't contain "server core" or "(core)" as a full-GUI (non-
// compliant) install. That premise is false: Microsoft's operatingSystem
// attribute reports the same string ("Windows Server 2019 Standard", etc.)
// for a Server Core install and a Desktop Experience install of the same
// edition - there is no LDAP attribute that distinguishes them (confirmed:
// the code's own prior comment already said "Microsoft does not provide a
// dedicated LDAP attribute", but the implementation still treated the
// absence of a substring that real DCs never carry as proof of
// non-compliance). A substring match against operatingSystem can therefore
// never observe a true "compliant" state - every DC, Server Core or not,
// fails the same way, which made the check structurally unable to confirm
// anything and turned every domain's R19+ finding into a guaranteed false
// positive. The only reliable source is the registry InstallationType value
// on each DC (HKLM\Software\Microsoft\Windows NT\CurrentVersion\
// InstallationType = "Server Core"), which is not collected over LDAP.
// Until that's collected, this detector reports the gap honestly instead of
// a fabricated verdict.

type R19ServerCoreNotUsedDetector struct{ audit.BaseDetector }

func NewR19ServerCoreNotUsedDetector() *R19ServerCoreNotUsedDetector {
	return &R19ServerCoreNotUsedDetector{
		BaseDetector: audit.NewBaseDetector("ANSSI_R19_SERVER_CORE_NOT_USED", audit.CategoryCompliance),
	}
}

func (d *R19ServerCoreNotUsedDetector) Detect(_ context.Context, data *audit.DetectorData) []types.Finding {
	dcs := data.DomainControllers
	if len(dcs) == 0 {
		return nil
	}

	return wrapFindingWithRepro(d, "ANSSI R19+ - Server Core usage cannot be confirmed via LDAP",
		fmt.Sprintf("ANSSI R19+ (p.35) recommends Windows Server Core on the Tier 0 perimeter to reduce attack surface. This cannot be verified through LDAP: the operatingSystem attribute reports the same string for a Server Core install and a Desktop Experience install of the same Windows Server edition, so no LDAP-only check can confirm or deny R19+ compliance. %d Domain Controller(s) in this domain - confirm directly on each host via the registry (HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\InstallationType = 'Server Core').", len(dcs)),
		types.SeverityInfo, len(dcs), computersToEntities(dcs, data.IncludeDetails),
		&types.FindingReproducibility{
			LDAPFilter: "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))",
			LDAPAttrs:  []string{"sAMAccountName", "operatingSystem"},
			Notes:      "LDAP's operatingSystem does not vary by install type and cannot confirm Server Core usage. Cross-check the InstallationType registry value on each DC instead.",
		})
}

// --- R40: no fine-grained password policy (PSO) covers Tier 0 admins ---
//
// v3.1.18 - uses helpers.Tier0Members + Tier0Groups for transitive Tier 0
// detection (recursive nesting + adminCount=1 + customer-supplied groups).
// Previous implementation (v3.1.17) only matched against 12 hardcoded group
// names directly, missing accounts hidden behind nested groups.

type R40NoPSOTier0Detector struct{ audit.BaseDetector }

func NewR40NoPSOTier0Detector() *R40NoPSOTier0Detector {
	return &R40NoPSOTier0Detector{
		BaseDetector: audit.NewBaseDetector("ANSSI_R40_NO_PSO_TIER0", audit.CategoryCompliance),
	}
}

func (d *R40NoPSOTier0Detector) Detect(_ context.Context, data *audit.DetectorData) []types.Finding {
	// v3.1.19 - pipe customer-supplied Tier 0 groups from tier0_groups.yaml.
	custom := tier0CustomGroups(data)
	tier0Groups := helpers.Tier0Groups(data, custom)
	tier0Users := helpers.Tier0Members(data, custom)
	if len(tier0Groups) == 0 && len(tier0Users) == 0 {
		return nil // can't decide
	}

	// A PSO "covers" Tier 0 if its AppliesTo references AT LEAST ONE Tier 0
	// group OR Tier 0 user. We do the recursive check via the helper sets.
	for _, p := range data.FGPPs {
		for _, applyTo := range p.AppliesTo {
			k := strings.ToLower(applyTo)
			if tier0Groups[k] || tier0Users[k] {
				return nil // covered
			}
		}
	}

	// Build entity list of the uncovered Tier 0 groups (cap at 100 to keep
	// JSON reasonable). EntityForDN resolves the type + sAMAccountName from
	// the engine's ObjectByDN cache so we don't emit a bare DN-only entity.
	var entities []types.AffectedEntity
	if data.IncludeDetails {
		// Sorted by DN: tier0Groups is a map, so ranging it
		// directly gives a randomized order per process, and the top-100 cap
		// below would then also keep a random subset - same input, different
		// JSON, different sha256 across runs.
		dns := make([]string, 0, len(tier0Groups))
		for dn := range tier0Groups {
			dns = append(dns, dn)
		}
		sort.Strings(dns)
		for _, dn := range dns {
			entities = append(entities, data.EntityForDN(dn))
			if len(entities) >= 100 {
				break
			}
		}
	}

	return wrapFindingWithRepro(d, "ANSSI R40 - Tier 0 admin groups are not covered by a fine-grained password policy",
		"ANSSI R40 requires applying stricter password policies (FGPP/PSO) to Tier 0 accounts than to regular users. "+
			fmt.Sprintf("None of the %d configured PSO(s) targets any of the %d Tier 0 group(s) or %d Tier 0 user(s) (recursive expansion + AdminSDHolder). ", len(data.FGPPs), len(tier0Groups), len(tier0Users))+
			"Create one PSO with stricter length/age/lockout settings and apply it to Domain Admins, Enterprise Admins, Schema Admins and the other privileged groups (or directly to user accounts).",
		types.SeverityHigh, len(tier0Groups), entities,
		&types.FindingReproducibility{
			LDAPBaseDN: "CN=Password Settings Container,CN=System," + extractDomainDN(data),
			LDAPFilter: "(objectClass=msDS-PasswordSettings)",
			LDAPAttrs:  []string{"cn", "msDS-PSOAppliesTo", "msDS-PasswordSettingsPrecedence"},
			Notes:      "Cross-reference msDS-PSOAppliesTo with the Tier 0 group/user DN set (Domain Admins, Enterprise Admins, Schema Admins, recursive members, AdminCount=1).",
		})
}

// extractDomainDN returns the domain DN from DetectorData. Empty when not
// available; callers concatenate gracefully (just produces a malformed
// suggestion, which is OK for a Notes field).
func extractDomainDN(data *audit.DetectorData) string {
	if data == nil || data.DomainInfo == nil {
		return ""
	}
	return data.DomainInfo.DomainDN
}

// computersToEntities converts a slice of Computer to AffectedEntity, honoring
// IncludeDetails. Defined here (vs lifecycle file) because Phase B is the first
// to need a Computer-side serializer.
//
// Uses the canonical mapper (types.ComputerToAffectedEntity, same one
// helpers.ToAffectedComputerEntities calls) instead of hand-building the
// entity: a prior local reimplementation here only set Type/DN/SAMAccountName,
// leaving Enabled/PasswordLastSet/LastLogon/MemberOf/OperatingSystem at their
// Go zero values - indistinguishable from a real disabled/unset account in
// the published JSON (caught confronting the r19 and r43 outputs).
func computersToEntities(comps []types.Computer, includeDetails bool) []types.AffectedEntity {
	if !includeDetails {
		return nil
	}
	out := make([]types.AffectedEntity, 0, len(comps))
	for i := range comps {
		out = append(out, types.ComputerToAffectedEntity(&comps[i]))
	}
	if len(out) > 100 {
		return out[:100]
	}
	return out
}

// tier0CustomGroups returns the customer-supplied Tier 0 group DNs from
// data.Tier0Config (loaded from tier0_groups.yaml by the audit engine).
// Returns nil when no config is loaded, which makes the helpers.Tier0*
// functions fall back to the hardcoded defaults.
//
// v3.1.19 - addresses the v3.1.18 honest gap where custom Tier 0 group
// names were unrecognized.
func tier0CustomGroups(data *audit.DetectorData) []string {
	if data == nil || data.Tier0Config == nil {
		return nil
	}
	return data.Tier0Config.Groups
}

func init() {
	audit.MustRegister(NewM12DefaultAdminNotRenamedDetector())
	audit.MustRegister(NewR15FunctionalLevelDetector())
	audit.MustRegister(NewR19ServerCoreNotUsedDetector())
	audit.MustRegister(NewR40NoPSOTier0Detector())
}
