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
		// An orphan here is an Entra user that claims to be on-prem synced but
		// has no meaningful activity or metadata typical of a healthy sync
		// (no last sign-in recorded, disabled account state, or stale creation).
		if u.AzureAccountEnabled != nil && !*u.AzureAccountEnabled {
			affected = append(affected, *u)
		}
	}

	finding := types.Finding{
		Type:     d.ID(),
		Severity: types.SeverityMedium,
		Category: string(d.Category()),
		Title:    "Potentially orphaned hybrid cloud user",
		Description: "Cloud user accounts flagged as on-prem synced are in a disabled state in " +
			"Entra ID. These may be leftovers from an on-prem deletion where Connect failed to " +
			"remove the cloud object, leaving a stale synced identity.",
		Count: len(affected),
		Details: map[string]interface{}{
			"recommendation": "Audit each listed user and delete obsolete cloud objects through Azure AD Connect or manually.",
		},
	}
	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
	}
	return []types.Finding{finding}
}

// HybridCloudOnlyPrivilegedDetector flags cloud-only (non-synced) users that
// hold privileged roles. Hybrid tenants generally enforce on-prem account
// origin for tier-0 assignments; cloud-only principals in privileged roles are
// worth reviewing even outside a full hybrid-posture audit.
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

	var cloudOnly []types.RoleAssignment
	for _, ra := range data.AzureRoleAssignments {
		if !privRoleIDs[ra.RoleID] {
			continue
		}
		if ra.PrincipalType != "" && ra.PrincipalType != "User" {
			continue
		}
		if !hybridIDs[ra.PrincipalID] {
			cloudOnly = append(cloudOnly, ra)
		}
	}

	finding := types.Finding{
		Type:     d.ID(),
		Severity: types.SeverityMedium,
		Category: string(d.Category()),
		Title:    "Cloud-only user assigned to privileged role",
		Description: "One or more privileged role assignments target cloud-only user accounts " +
			"(no on-premises sync). In hybrid tenants this can be intentional for break-glass accounts, " +
			"but otherwise represents a gap in the usual tier-0 governance.",
		Count: len(cloudOnly),
		Details: map[string]interface{}{
			"recommendation": "Verify each cloud-only privileged account is intentional (e.g. break-glass) and documented.",
		},
	}
	if data.IncludeDetails && len(cloudOnly) > 0 {
		finding.AffectedEntities = helpers.RoleAssignmentsToAffectedEntities(cloudOnly)
	}
	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewHybridOrphanedCloudUserDetector())
	audit.MustRegister(NewHybridCloudOnlyPrivilegedDetector())
}
