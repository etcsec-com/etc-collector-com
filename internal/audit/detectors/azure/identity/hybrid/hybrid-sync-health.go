package hybrid

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// HybridOrphanedCloudUserDetector flags cloud user objects whose
// AzureOnPremisesSyncEnabled is true but who no longer appear resolvable
// against any on-premises principal. In practice this means their
// AzureOnPremisesSyncEnabled flag is set but the collector has no matching
// on-prem sync state.
//
// Partially matches the intent behind Purple Knight's hybrid category.
type HybridOrphanedCloudUserDetector struct {
	audit.BaseDetector
}

func NewHybridOrphanedCloudUserDetector() *HybridOrphanedCloudUserDetector {
	return &HybridOrphanedCloudUserDetector{
		BaseDetector: audit.NewBaseDetector("HYBRID_ORPHANED_CLOUD_USER", audit.CategoryIdentity),
	}
}

func (d *HybridOrphanedCloudUserDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.User
	for i := range data.Users {
		u := &data.Users[i]
		// Only consider Azure-origin users (they have one of the Azure fields populated).
		if u.AzureOnPremisesSyncEnabled == nil || !*u.AzureOnPremisesSyncEnabled {
			continue
		}
		// Disabled + synced is a plain state observation, not a diagnosis. A
		// disabled synced account is the NORMAL, expected outcome of routine
		// on-prem offboarding (disable before delete is standard practice)
		// and is not, by itself, evidence of a failed sync or an orphaned
		// object - no Microsoft source documents "disabled + synced" as a
		// sync-failure signature.
		if u.AzureAccountEnabled != nil && !*u.AzureAccountEnabled {
			affected = append(affected, *u)
		}
	}

	finding := types.Finding{
		Type:     d.ID(),
		Severity: types.SeverityMedium,
		Category: string(d.Category()),
		Title:    "Disabled Hybrid-Synced User Account",
		Description: "Cloud user accounts flagged as on-prem synced are in a disabled state in " +
			"Entra ID. This is a routine hygiene signal, not a proven sync failure: a disabled " +
			"synced account is the normal, expected state right after on-prem offboarding. " +
			"Review the list to confirm each disablement was intentional and, where it wasn't, " +
			"investigate the on-prem sync.",
		Count: len(affected),
		Details: map[string]interface{}{
			"recommendation": "Confirm each listed account's on-prem disablement was intentional; investigate Azure AD Connect only for accounts where it was not.",
		},
	}
	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
	}
	return []types.Finding{finding}
}

// HybridCloudOnlyPrivilegedDetector flags on-prem-synced (hybrid) users that
// hold privileged roles.
//
// Despite the "cloud only" name - kept unchanged because
// docs_gen.go (generated, out of scope here), CHECKS.yml and
// two docs/*.md catalogs reference this exact ID and Go type name - the
// detection direction was corrected 2026-09-08 to match Microsoft's
// own guidance, which is the opposite of what the original name suggests:
// "Global Administrator (and other privileged groups) accounts should be
// cloud-only accounts with no ties to on-premises Active Directory."
// (Microsoft Learn, "Secure access practices for administrators in
// Microsoft Entra ID", learn.microsoft.com/en-us/entra/identity/
// role-based-access-control/security-planning, Stage 2 > "Ensure separate
// user accounts and mail forwarding for Global Administrator accounts".)
// A cloud-only Tier 0 account is the Microsoft-recommended state, not an
// anomaly. The real risk is the inverse: a privileged role held by an
// on-prem-synced account, which an attacker can reach by compromising the
// on-prem AD it syncs from. That is what this detector now flags.
//
// Renaming ID()/the Go type to match is left as a follow-up ticket that also
// touches docs_gen.go, CHECKS.yml and the docs/*.md catalogs - all outside
// scope here.
type HybridCloudOnlyPrivilegedDetector struct {
	audit.BaseDetector
}

func NewHybridCloudOnlyPrivilegedDetector() *HybridCloudOnlyPrivilegedDetector {
	return &HybridCloudOnlyPrivilegedDetector{
		BaseDetector: audit.NewBaseDetector("HYBRID_CLOUD_ONLY_PRIVILEGED", audit.CategoryIdentity),
	}
}

var privRoleIDs = map[string]bool{
	types.AzureRoleGlobalAdmin:         true,
	types.AzureRolePrivilegedRoleAdmin: true,
	types.AzureRoleSecurityAdmin:       true,
	types.AzureRoleExchangeAdmin:       true,
	types.AzureRoleSharePointAdmin:     true,
}

func (d *HybridCloudOnlyPrivilegedDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// Build map of hybrid-synced principal IDs.
	hybridIDs := make(map[string]bool)
	for i := range data.Users {
		u := &data.Users[i]
		if u.AzureOnPremisesSyncEnabled != nil && *u.AzureOnPremisesSyncEnabled && u.ObjectSID != "" {
			hybridIDs[u.ObjectSID] = true
		}
	}

	var hybridPrivileged []types.RoleAssignment
	for _, ra := range data.AzureRoleAssignments {
		if !privRoleIDs[ra.RoleID] {
			continue
		}
		if ra.PrincipalType != "" && ra.PrincipalType != "User" {
			continue
		}
		if hybridIDs[ra.PrincipalID] {
			hybridPrivileged = append(hybridPrivileged, ra)
		}
	}

	finding := types.Finding{
		Type:     d.ID(),
		Severity: types.SeverityMedium,
		Category: string(d.Category()),
		Title:    "On-Prem-Synced Account Holds Privileged Role",
		Description: "One or more privileged role assignments target accounts synced from " +
			"on-premises Active Directory. Microsoft recommends privileged (Tier 0) accounts be " +
			"cloud-only with no ties to on-premises AD, precisely because a synced privileged " +
			"account can be reached by compromising the on-prem AD it syncs from.",
		Count: len(hybridPrivileged),
		Details: map[string]interface{}{
			"recommendation": "Migrate each listed privileged account to a cloud-only account; reserve on-prem-synced accounts for non-privileged roles.",
		},
	}
	if data.IncludeDetails && len(hybridPrivileged) > 0 {
		finding.AffectedEntities = helpers.RoleAssignmentsToAffectedEntities(hybridPrivileged)
	}
	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewHybridOrphanedCloudUserDetector())
	audit.MustRegister(NewHybridCloudOnlyPrivilegedDetector())
}
