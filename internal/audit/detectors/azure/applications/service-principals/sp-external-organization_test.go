package serviceprincipals

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

const (
	// A placeholder, deliberately not a real tenant: this file ships publicly.
	// The identifier of an actual tenant has no business in a test - it is not
	// a secret, but publishing which tenant was audited is nobody's business
	// but its owner's.
	thisTenant        = "00000000-1111-2222-3333-444444444444"
	microsoftServices = "f8cdef31-a31e-4b4a-93e4-5f571e91255a"
	microsoftCorp     = "72f988bf-86f1-41af-91ab-2d7cd011db47"
	consumerAccounts  = "9188040d-6c67-4c5b-b112-36a304b66dad"
)

func sp(name, owner string) types.ServicePrincipal {
	return types.ServicePrincipal{
		DisplayName:            name,
		AppOwnerOrganizationID: owner,
		ServicePrincipalType:   "Application",
	}
}

func count(t *testing.T, data *audit.DetectorData) int {
	t.Helper()
	f := NewSPExternalOrganizationDetector().Detect(context.Background(), data)
	if len(f) == 0 {
		return -1 // the detector deliberately said nothing
	}
	return f[0].Count
}

// The shape measured on a real tenant on 2026-09-08: 100 service principals, of
// which 76 were Microsoft platform services, 3 were the tenant's own apps, and
// only 21 belonged to an outside organisation. Before this fix the check
// reported all of them.
func TestSPExternalOrganization_CountsOnlyOutsideOrganisations(t *testing.T) {
	data := &audit.DetectorData{
		AzureTenantID: thisTenant,
		AzureServicePrincipals: []types.ServicePrincipal{
			sp("Microsoft To-Do", microsoftServices),
			sp("Microsoft Teams Templates Service", microsoftServices),
			sp("Graph Explorer", microsoftCorp),
			sp("OGGERI_HA", thisTenant),
			sp("OAuth2-API", thisTenant),
			sp("Atlassian", "439cd382-947c-487d-a18f-fd64237bec72"),
			sp("HubSpot Sales", "10ac92ed-06ba-4584-87f3-22e6154f683d"),
			sp("AddEvent.com", consumerAccounts),
		},
	}

	// Atlassian, HubSpot, and the consumer-registered vendor. Not Microsoft's
	// platform services, not this tenant's own applications.
	if got := count(t, data); got != 3 {
		t.Fatalf("count = %d, want 3 (only the outside organisations)\n"+
			"a count of 8 means nothing is excluded; 5 means Microsoft's tenants are not excluded; "+
			"6 means this tenant's own applications are not excluded", got)
	}
}

// Each exclusion, alone, so a regression names itself instead of moving one
// aggregate number.
func TestSPExternalOrganization_ExcludesOwnTenant(t *testing.T) {
	data := &audit.DetectorData{
		AzureTenantID:          thisTenant,
		AzureServicePrincipals: []types.ServicePrincipal{sp("OGGERI_HA", thisTenant)},
	}
	if got := count(t, data); got != 0 {
		t.Fatalf("count = %d, want 0 - an application whose home tenant IS this tenant "+
			"is not owned by an outside organisation", got)
	}
}

func TestSPExternalOrganization_ExcludesMicrosoftPlatformServices(t *testing.T) {
	for _, tenant := range []string{microsoftServices, microsoftCorp} {
		data := &audit.DetectorData{
			AzureTenantID:          thisTenant,
			AzureServicePrincipals: []types.ServicePrincipal{sp("Microsoft To-Do", tenant)},
		}
		if got := count(t, data); got != 0 {
			t.Fatalf("count = %d for Microsoft tenant %s, want 0 - these platform services sit in "+
				"every tenant and bury the third-party access that matters", got, tenant)
		}
	}
}

// A consumer-registered vendor is still an outside organisation, and is still
// reported. This locks the exclusions to what is documented and no wider.
func TestSPExternalOrganization_StillReportsConsumerRegisteredVendors(t *testing.T) {
	data := &audit.DetectorData{
		AzureTenantID:          thisTenant,
		AzureServicePrincipals: []types.ServicePrincipal{sp("AddEvent.com", consumerAccounts)},
	}
	if got := count(t, data); got != 1 {
		t.Fatalf("count = %d, want 1 - a vendor that also registers for personal accounts is "+
			"still a third party the operator wants to see", got)
	}
}

// Without the tenant's own identity the first exclusion cannot be applied, and
// the count would be knowingly wrong. Silence beats a wrong number.
func TestSPExternalOrganization_SilentWithoutTenantIdentity(t *testing.T) {
	data := &audit.DetectorData{
		AzureServicePrincipals: []types.ServicePrincipal{sp("Atlassian", "439cd382-947c-487d-a18f-fd64237bec72")},
	}
	if got := count(t, data); got != -1 {
		t.Fatalf("detector produced a finding (count=%d) without knowing which tenant it is "+
			"looking at - it cannot tell internal from external, so it must stay silent", got)
	}
}

// Managed identities have never been in scope: they are the tenant's own
// workload identities, not an outside organisation's application.
func TestSPExternalOrganization_IgnoresManagedIdentities(t *testing.T) {
	mi := sp("some-managed-identity", "439cd382-947c-487d-a18f-fd64237bec72")
	mi.ServicePrincipalType = "ManagedIdentity"
	data := &audit.DetectorData{AzureTenantID: thisTenant, AzureServicePrincipals: []types.ServicePrincipal{mi}}
	if got := count(t, data); got != 0 {
		t.Fatalf("count = %d, want 0 - managed identities are this tenant's own workload identities", got)
	}
}
