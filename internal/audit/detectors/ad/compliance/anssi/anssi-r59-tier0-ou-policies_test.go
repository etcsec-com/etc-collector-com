package anssi

import (
	"context"
	"strings"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// --- R59 ---

func r59BaseData(domainDN string, tier0OU types.OU, gpoDN, gpoGUID string) *audit.DetectorData {
	return &audit.DetectorData{
		DomainInfo: &types.DomainInfo{DomainDN: domainDN},
		OUs:        []types.OU{tier0OU},
		GPOs:       []types.GPO{{DN: gpoDN, GUID: gpoGUID}},
	}
}

func TestR59Tier0OUPolicies_Detect(t *testing.T) {
	domainDN := "DC=test,DC=local"
	tier0OU := types.OU{DN: "OU=Tier0," + domainDN}
	gpoGUID := "aaaaaaaa-1111-2222-3333-444444444444"
	gpoDN := "CN={" + gpoGUID + "},CN=Policies,CN=System," + domainDN

	t.Run("weak-ACL GPO linked to Tier0 OU -> flagged", func(t *testing.T) {
		data := r59BaseData(domainDN, tier0OU, gpoDN, gpoGUID)
		data.GPOAcls = []audit.GPOAcl{
			{GPODN: gpoDN, Trustee: "S-1-5-21-1-2-3-1105", AccessMask: types.MaskWriteDACL, AceType: "ACCESS_ALLOWED"},
		}
		data.GPOLinks = []audit.GPOLink{
			{GPOCN: gpoGUID, LinkedTo: tier0OU.DN, LinkEnabled: true},
		}
		d := NewR59Tier0OUPoliciesDetector()
		findings := d.Detect(context.Background(), data)
		if len(findings) != 1 || findings[0].Count == 0 {
			t.Fatalf("expected a flagged finding, got %+v", findings)
		}
	})

	t.Run("GPO linked but ACL not weak -> clean", func(t *testing.T) {
		data := r59BaseData(domainDN, tier0OU, gpoDN, gpoGUID)
		data.GPOLinks = []audit.GPOLink{
			{GPOCN: gpoGUID, LinkedTo: tier0OU.DN, LinkEnabled: true},
		}
		d := NewR59Tier0OUPoliciesDetector()
		findings := d.Detect(context.Background(), data)
		if len(findings) != 0 {
			t.Fatalf("expected no finding, got %+v", findings)
		}
	})

	t.Run("weak-ACL GPO linked elsewhere, not to Tier0 OU -> clean", func(t *testing.T) {
		data := r59BaseData(domainDN, tier0OU, gpoDN, gpoGUID)
		data.GPOAcls = []audit.GPOAcl{
			{GPODN: gpoDN, Trustee: "S-1-5-21-1-2-3-1105", AccessMask: types.MaskWriteDACL, AceType: "ACCESS_ALLOWED"},
		}
		data.GPOLinks = []audit.GPOLink{
			{GPOCN: gpoGUID, LinkedTo: "OU=Sales," + domainDN, LinkEnabled: true},
		}
		d := NewR59Tier0OUPoliciesDetector()
		findings := d.Detect(context.Background(), data)
		if len(findings) != 0 {
			t.Fatalf("expected no finding, got %+v", findings)
		}
	})

	t.Run("no Tier0 OU present -> no finding, nothing to evaluate", func(t *testing.T) {
		data := &audit.DetectorData{DomainInfo: &types.DomainInfo{DomainDN: domainDN}}
		d := NewR59Tier0OUPoliciesDetector()
		findings := d.Detect(context.Background(), data)
		if len(findings) != 0 {
			t.Fatalf("expected no finding, got %+v", findings)
		}
	})
}

// the finding used to claim full R59 coverage. It only checks one
// of R59's three components (weak-ACL GPOs linked to the Tier 0 OU); it
// can't verify inheritance blocking (data not collected) or the Default
// Domain Policy priority requirement. The description must say so.
func TestR59Tier0OUPolicies_ScopeHonestlyAnnounced(t *testing.T) {
	domainDN := "DC=test,DC=local"
	tier0OU := types.OU{DN: "OU=Tier0," + domainDN}
	gpoGUID := "bbbbbbbb-1111-2222-3333-444444444444"
	gpoDN := "CN={" + gpoGUID + "},CN=Policies,CN=System," + domainDN
	data := r59BaseData(domainDN, tier0OU, gpoDN, gpoGUID)
	data.GPOAcls = []audit.GPOAcl{
		{GPODN: gpoDN, Trustee: "S-1-5-21-1-2-3-1105", AccessMask: types.MaskWriteDACL, AceType: "ACCESS_ALLOWED"},
	}
	data.GPOLinks = []audit.GPOLink{
		{GPOCN: gpoGUID, LinkedTo: tier0OU.DN, LinkEnabled: true},
	}
	d := NewR59Tier0OUPoliciesDetector()
	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	desc := strings.ToLower(findings[0].Description)
	if !strings.Contains(desc, "does not verify") && !strings.Contains(desc, "does not observe") {
		t.Errorf("description should honestly disclose uncovered R59 scope, got %q", findings[0].Description)
	}
}
