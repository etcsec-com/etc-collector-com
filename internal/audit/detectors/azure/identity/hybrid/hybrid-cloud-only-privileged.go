package hybrid

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

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
	audit.MustRegister(NewHybridCloudOnlyPrivilegedDetector())
}
