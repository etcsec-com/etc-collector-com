package anssi

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

func denyAll() *int {
	v := 2
	return &v
}

func auditOnly() *int {
	v := 1
	return &v
}

// R73 previously matched on ANY GPO setting the registry value,
// with zero check that the GPO was actually linked to Tier 0. A GPO with
// the right value linked to an unrelated OU used to pass R73 - a false
// negative. It must now require the GPO to be link-enabled at the domain
// root, a Tier 0 OU, or the Domain Controllers container.
func TestR73NTLMOutboundTier0_Detect(t *testing.T) {
	domainDN := "DC=test,DC=local"

	gpoLinkedNowhereUseful := &audit.GPOPolicy{
		GUID:             "11111111-1111-1111-1111-111111111111",
		RegistrySettings: &audit.RegistrySettings{RestrictSendingNTLMTraffic: denyAll()},
	}
	gpoLinkedToDC := &audit.GPOPolicy{
		GUID:             "22222222-2222-2222-2222-222222222222",
		RegistrySettings: &audit.RegistrySettings{RestrictSendingNTLMTraffic: denyAll()},
	}
	gpoLinkedToDomainRoot := &audit.GPOPolicy{
		GUID:             "33333333-3333-3333-3333-333333333333",
		RegistrySettings: &audit.RegistrySettings{RestrictSendingNTLMTraffic: denyAll()},
	}
	gpoAuditOnlyLinkedToDC := &audit.GPOPolicy{
		GUID:             "44444444-4444-4444-4444-444444444444",
		RegistrySettings: &audit.RegistrySettings{RestrictSendingNTLMTraffic: auditOnly()},
	}

	cases := []struct {
		name        string
		policies    map[string]*audit.GPOPolicy
		links       []audit.GPOLink
		wantFlagged bool
	}{
		{
			name:     "value set but linked to an unrelated OU -> still flagged (was the  false negative)",
			policies: map[string]*audit.GPOPolicy{gpoLinkedNowhereUseful.GUID: gpoLinkedNowhereUseful},
			links: []audit.GPOLink{
				{GPOGuid: gpoLinkedNowhereUseful.GUID, LinkedTo: "OU=Workstations," + domainDN, LinkEnabled: true},
			},
			wantFlagged: true,
		},
		{
			name:     "value set and linked to Domain Controllers OU -> met",
			policies: map[string]*audit.GPOPolicy{gpoLinkedToDC.GUID: gpoLinkedToDC},
			links: []audit.GPOLink{
				{GPOGuid: gpoLinkedToDC.GUID, LinkedTo: "OU=Domain Controllers," + domainDN, LinkEnabled: true},
			},
			wantFlagged: false,
		},
		{
			name:     "value set and linked to domain root -> met (domain-wide is a superset of Tier 0)",
			policies: map[string]*audit.GPOPolicy{gpoLinkedToDomainRoot.GUID: gpoLinkedToDomainRoot},
			links: []audit.GPOLink{
				{GPOGuid: gpoLinkedToDomainRoot.GUID, LinkedTo: domainDN, LinkEnabled: true},
			},
			wantFlagged: false,
		},
		{
			name:     "audit-only (=1) even when linked to DC OU -> not enough, flagged",
			policies: map[string]*audit.GPOPolicy{gpoAuditOnlyLinkedToDC.GUID: gpoAuditOnlyLinkedToDC},
			links: []audit.GPOLink{
				{GPOGuid: gpoAuditOnlyLinkedToDC.GUID, LinkedTo: "OU=Domain Controllers," + domainDN, LinkEnabled: true},
			},
			wantFlagged: true,
		},
		{
			name:     "link disabled -> not counted, flagged",
			policies: map[string]*audit.GPOPolicy{gpoLinkedToDC.GUID: gpoLinkedToDC},
			links: []audit.GPOLink{
				{GPOGuid: gpoLinkedToDC.GUID, LinkedTo: "OU=Domain Controllers," + domainDN, LinkEnabled: false},
			},
			wantFlagged: true,
		},
		{
			name:        "no GPO at all -> flagged",
			policies:    map[string]*audit.GPOPolicy{},
			links:       nil,
			wantFlagged: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data := &audit.DetectorData{
				DomainInfo:  &types.DomainInfo{DomainDN: domainDN},
				GPOPolicies: tc.policies,
				GPOLinks:    tc.links,
			}
			d := NewR73NTLMOutboundTier0Detector()
			findings := d.Detect(context.Background(), data)
			flagged := len(findings) == 1 && findings[0].Count > 0
			if flagged != tc.wantFlagged {
				t.Errorf("flagged = %v, want %v (findings=%+v)", flagged, tc.wantFlagged, findings)
			}
		})
	}
}

func TestR73NTLMOutboundTier0_CustomTier0OU(t *testing.T) {
	domainDN := "DC=test,DC=local"
	gpo := &audit.GPOPolicy{
		GUID:             "55555555-5555-5555-5555-555555555555",
		RegistrySettings: &audit.RegistrySettings{RestrictSendingNTLMTraffic: denyAll()},
	}
	data := &audit.DetectorData{
		DomainInfo:  &types.DomainInfo{DomainDN: domainDN},
		GPOPolicies: map[string]*audit.GPOPolicy{gpo.GUID: gpo},
		GPOLinks: []audit.GPOLink{
			{GPOGuid: gpo.GUID, LinkedTo: "OU=SecureAdmin," + domainDN, LinkEnabled: true},
		},
		Tier0Config: &audit.Tier0HelperConfig{OUs: []string{"OU=SecureAdmin," + domainDN}},
	}
	d := NewR73NTLMOutboundTier0Detector()
	findings := d.Detect(context.Background(), data)
	if len(findings) != 0 {
		t.Errorf("expected R73 met via tier0_groups.yaml custom OU, got %+v", findings)
	}
}
