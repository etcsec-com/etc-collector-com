package serviceprincipals

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

const (
	IDSPExternalOrganization       = "SP_EXTERNAL_ORGANIZATION"
	CategorySPExternalOrganization = audit.CategoryApplications
)

type SPExternalOrganizationDetector struct {
	audit.BaseDetector
}

func NewSPExternalOrganizationDetector() *SPExternalOrganizationDetector {
	return &SPExternalOrganizationDetector{
		BaseDetector: audit.NewBaseDetector(IDSPExternalOrganization, CategorySPExternalOrganization),
	}
}

// microsoftOwnedTenants are the Microsoft tenants that own the platform
// service principals present in every Entra tenant. Both values are quoted
// from Microsoft Learn, "Verify first-party Microsoft applications in sign-in
// reports" (updated 2026-03-19) - not inferred from observation.
var microsoftOwnedTenants = map[string]bool{
	// "the Microsoft Service's Microsoft Entra tenant ID"
	"f8cdef31-a31e-4b4a-93e4-5f571e91255a": true,
	// the tenant listed as owning "Microsoft tenant-owned applications"
	"72f988bf-86f1-41af-91ab-2d7cd011db47": true,
}

func (d *SPExternalOrganizationDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affectedSPs []types.ServicePrincipal

	// AppOwnerOrganizationID is the app's HOME TENANT, never a flag meaning
	// "external". It is set on nearly every application-backed service
	// principal, this tenant's own applications and Microsoft's platform
	// services included. Reading it alone is what made this check report
	// every service principal in the directory.
	//
	// Measured on a real tenant (2026-09-08), 100 service principals:
	//   76  Microsoft Services tenant   (Microsoft To-Do, Teams Templates, ...)
	//    3  this tenant's own apps
	//   21  genuinely another organisation (Atlassian, HubSpot, Adobe, ...)
	// The check reported all 100. The answer an operator needs is the 21.
	//
	// Two exclusions, each defensible on its own terms:
	//
	//  1. This tenant's own ID. Arithmetic, not judgement: an application
	//     whose home tenant IS this tenant is by definition not owned by an
	//     outside organisation.
	//
	//  2. Microsoft's own tenants. Source: Microsoft Learn, "Verify
	//     first-party Microsoft applications in sign-in reports"
	//     (learn.microsoft.com/troubleshoot/entra/entra-id/governance/
	//     verify-first-party-apps-sign-in, updated 2026-03-19), which states
	//     that f8cdef31-a31e-4b4a-93e4-5f571e91255a "is the Microsoft
	//     Service's Microsoft Entra tenant ID", and lists
	//     72f988bf-86f1-41af-91ab-2d7cd011db47 as the tenant owning Microsoft
	//     tenant-owned applications. These are platform services present in
	//     every tenant; listing them as third-party access buries the finding
	//     that matters under noise the operator cannot act on.
	//
	// Deliberately still reported: applications whose home tenant is the
	// consumer-account tenant. Those are real outside vendors that happen to
	// register for personal accounts too, and an operator does want to see
	// them.
	//
	// When AzureTenantID is empty (a provider that cannot say which tenant it
	// is looking at), exclusion 1 cannot be applied. The check then stays
	// silent rather than reporting a count it knows is wrong.
	if data.AzureTenantID == "" {
		return nil
	}

	for _, sp := range data.AzureServicePrincipals {
		if sp.ServicePrincipalType == "ManagedIdentity" || sp.AppOwnerOrganizationID == "" {
			continue
		}
		if sp.AppOwnerOrganizationID == data.AzureTenantID {
			continue
		}
		if microsoftOwnedTenants[sp.AppOwnerOrganizationID] {
			continue
		}
		affectedSPs = append(affectedSPs, sp)
	}

	finding := types.Finding{
		Type:        IDSPExternalOrganization,
		Severity:    types.SeverityMedium,
		Category:    string(CategorySPExternalOrganization),
		Title:       "Service Principals from External Organizations",
		Description: "Service principals owned by an outside organisation have access to your tenant. Applications belonging to this tenant and Microsoft's own platform services are excluded - what is counted here is third-party access. Verify each one still needs it.",
		Count:       len(affectedSPs),
	}

	if data.IncludeDetails && len(affectedSPs) > 0 {
		finding.AffectedEntities = helpers.ToAffectedServicePrincipalEntities(affectedSPs)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewSPExternalOrganizationDetector())
}
