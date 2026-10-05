package network

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
)

func TestSubnetMissing_SiteWithSubnet_NotCounted(t *testing.T) {
	findings := NewSubnetMissingDetector().Detect(context.Background(), &audit.DetectorData{
		Sites: []audit.Site{
			{Name: "HQ", DistinguishedName: "CN=HQ,CN=Sites,CN=Configuration,DC=example,DC=com"},
		},
		Subnets: []audit.Subnet{
			{
				Name:              "10.0.0.0/24",
				DistinguishedName: "CN=10.0.0.0/24,CN=Subnets,CN=Sites,CN=Configuration,DC=example,DC=com",
				SiteDN:            "CN=HQ,CN=Sites,CN=Configuration,DC=example,DC=com",
			},
		},
	})
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.Count != 0 {
		t.Fatalf("expected 0 sites without a subnet, got count=%d", f.Count)
	}
}

func TestSubnetMissing_SiteWithoutSubnet_Counted(t *testing.T) {
	findings := NewSubnetMissingDetector().Detect(context.Background(), &audit.DetectorData{
		Sites: []audit.Site{
			{Name: "Branch", DistinguishedName: "CN=Branch,CN=Sites,CN=Configuration,DC=example,DC=com"},
		},
	})
	f := findings[0]
	if f.Count != 1 {
		t.Fatalf("expected 1 site without a subnet, got count=%d", f.Count)
	}
}

// TestSubnetMissing_CaseInsensitiveSiteDN pins the strings.EqualFold match
// between Subnet.SiteDN and Site.DistinguishedName: a subnet whose SiteDN
// differs from the site's DN only by case must still count as "has a
// subnet" - a case-sensitive comparison would wrongly flag this site as
// missing one.
func TestSubnetMissing_CaseInsensitiveSiteDN(t *testing.T) {
	findings := NewSubnetMissingDetector().Detect(context.Background(), &audit.DetectorData{
		Sites: []audit.Site{
			{Name: "HQ", DistinguishedName: "CN=HQ,CN=Sites,CN=Configuration,DC=example,DC=com"},
		},
		Subnets: []audit.Subnet{
			{
				Name:              "10.0.0.0/24",
				DistinguishedName: "CN=10.0.0.0/24,CN=Subnets,CN=Sites,CN=Configuration,DC=example,DC=com",
				SiteDN:            "cn=hq,cn=sites,cn=configuration,dc=example,dc=com",
			},
		},
	})
	f := findings[0]
	if f.Count != 0 {
		t.Fatalf("expected EqualFold to match despite case difference, got count=%d", f.Count)
	}
}

func TestSubnetMissing_NoSites(t *testing.T) {
	findings := NewSubnetMissingDetector().Detect(context.Background(), &audit.DetectorData{})
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.Count != 0 {
		t.Fatalf("expected 0 with no sites at all, got count=%d", f.Count)
	}
}
