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

// ANSSI-PA-099 R40 - no fine-grained password policy (PSO) covers Tier 0
// admins.
//
// R40: Appliquer des stratégies de mot de passe affinées (FGPP/PSO) pour les
// comptes du Tier 0.
//
// Source: https://messervices.cyber.gouv.fr/documents-guides/anssi-guide-admin_securisee_si_ad_v1-0%20(3).pdf
//
// v3.1.18 - uses helpers.Tier0Members + Tier0Groups for transitive Tier 0
// detection (well-known SID seed set + DnsAdmins by name, recursive nesting,
// customer-supplied groups). Previous implementation (v3.1.17) only matched
// against 12 hardcoded group names directly, missing accounts hidden behind
// nested groups.

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
			fmt.Sprintf("None of the %d configured PSO(s) targets any of the %d Tier 0 group(s) or %d Tier 0 user(s) (Tier 0 recognized by well-known SID for the fixed-RID groups, by name for DnsAdmins, recursive group nesting, and tier0_groups.yaml customer config). ", len(data.FGPPs), len(tier0Groups), len(tier0Users))+
			"Create one PSO with stricter length/age/lockout settings and apply it to Domain Admins, Enterprise Admins, Schema Admins and the other privileged groups (or directly to user accounts).",
		types.SeverityHigh, len(tier0Groups), entities,
		&types.FindingReproducibility{
			LDAPBaseDN: "CN=Password Settings Container,CN=System," + extractDomainDN(data),
			LDAPFilter: "(objectClass=msDS-PasswordSettings)",
			LDAPAttrs:  []string{"cn", "msDS-PSOAppliesTo", "msDS-PasswordSettingsPrecedence"},
			Notes:      "Cross-reference msDS-PSOAppliesTo with the Tier 0 group/user DN set (Domain Admins, Enterprise Admins, Schema Admins, DnsAdmins, recursive members).",
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
	audit.MustRegister(NewR40NoPSOTier0Detector())
}
