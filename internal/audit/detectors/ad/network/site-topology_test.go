package network

import (
	"context"
	"strings"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
)

// TestSiteTopology_TitleMatchesWhatIsMeasured is RED on the pre-fix
// detector: it was titled/described as general "AD Site Topology Issues"
// (site links, replication costs, orphaned subnets) while Detect() only ever
// checked len(site.Servers) == 0. None of site links, replication costs or
// subnet-to-site mappings are collected anywhere in this codebase, so the
// title must not promise them.
func TestSiteTopology_TitleMatchesWhatIsMeasured(t *testing.T) {
	findings := NewSiteTopologyDetector().Detect(context.Background(), &audit.DetectorData{})
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	f := findings[0]

	if strings.Contains(f.Title, "Topology") {
		t.Errorf("title must not claim general topology coverage it doesn't measure, got %q", f.Title)
	}
	if !strings.Contains(strings.ToLower(f.Description), "site links") && !strings.Contains(strings.ToLower(f.Description), "does not evaluate") {
		t.Errorf("description must disclose that site links/replication costs/subnets are not evaluated, got %q", f.Description)
	}
}

func TestSiteTopology_FlagsSiteWithoutDC(t *testing.T) {
	findings := NewSiteTopologyDetector().Detect(context.Background(), &audit.DetectorData{
		Sites: []audit.Site{
			{Name: "HQ", Servers: []string{"dc1"}},
			{Name: "Branch", Servers: nil},
		},
	})
	f := findings[0]
	if f.Count != 1 {
		t.Fatalf("expected 1 site without a DC, got count=%d", f.Count)
	}
}

// TestSiteTopology_IdentifiesTheCorrectSite guards against a mutation that
// shifts WHICH site is flagged while leaving Count coincidentally right (a
// two-site fixture where a wrong condition happens to also match exactly
// one site cannot be caught by asserting Count alone) - it asserts the
// actual site name reported in Details.
func TestSiteTopology_IdentifiesTheCorrectSite(t *testing.T) {
	findings := NewSiteTopologyDetector().Detect(context.Background(), &audit.DetectorData{
		Sites: []audit.Site{
			{Name: "HQ", Servers: []string{"dc1"}},
			{Name: "Branch", Servers: nil},
		},
	})
	f := findings[0]
	names, ok := f.Details["sitesWithoutDc"].([]string)
	if !ok || len(names) != 1 || names[0] != "Branch" {
		t.Fatalf("expected sitesWithoutDc=[Branch], got %#v", f.Details["sitesWithoutDc"])
	}
}
