package network

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

func detectNtp(t *testing.T, data *audit.DetectorData) types.Finding {
	t.Helper()
	findings := NewNtpDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	return findings[0]
}

// TestNtp_TwoActiveDCs_EntitiesCarryRealDNAndEnabled proves that affected
// entities come from the real DC objects, not from a rebuild off
// sAMAccountName alone.
func TestNtp_TwoActiveDCs_EntitiesCarryRealDNAndEnabled(t *testing.T) {
	f := detectNtp(t, &audit.DetectorData{
		IncludeDetails: true,
		DomainControllers: []types.Computer{
			{DN: "CN=DC1,OU=Domain Controllers,DC=example,DC=com", SAMAccountName: "DC1$", Disabled: false},
			{DN: "CN=DC2,OU=Domain Controllers,DC=example,DC=com", SAMAccountName: "DC2$", Disabled: false},
		},
	})
	if f.Count != 1 {
		t.Fatalf("expected count=1 for a domain with 2 DCs, got %d", f.Count)
	}
	if len(f.AffectedEntities) != 2 {
		t.Fatalf("expected 2 affected entities, got %d", len(f.AffectedEntities))
	}
	for i, want := range []struct {
		dn  string
		sam string
	}{
		{"CN=DC1,OU=Domain Controllers,DC=example,DC=com", "DC1$"},
		{"CN=DC2,OU=Domain Controllers,DC=example,DC=com", "DC2$"},
	} {
		e := f.AffectedEntities[i]
		if e.DN != want.dn {
			t.Errorf("entity %d: expected DN %q, got %q", i, want.dn, e.DN)
		}
		if e.SAMAccountName != want.sam {
			t.Errorf("entity %d: expected SAMAccountName %q, got %q", i, want.sam, e.SAMAccountName)
		}
		if !e.Enabled {
			t.Errorf("entity %d (%s): expected Enabled=true, got false", i, want.sam)
		}
	}
}

// TestNtp_SingleDC_NotCounted covers the no-finding branch: a domain with
// only one DC never triggers this check.
func TestNtp_SingleDC_NotCounted(t *testing.T) {
	f := detectNtp(t, &audit.DetectorData{
		IncludeDetails: true,
		DomainControllers: []types.Computer{
			{DN: "CN=DC1,OU=Domain Controllers,DC=example,DC=com", SAMAccountName: "DC1$", Disabled: false},
		},
	})
	if f.Count != 0 {
		t.Fatalf("expected count=0 for a single-DC domain, got %d", f.Count)
	}
}

// TestNtp_OneDisabledDC_EntitiesReflectRealState proves that a disabled DC
// shows enabled=false while an active one in the same finding shows
// enabled=true - the two must not be conflated.
func TestNtp_OneDisabledDC_EntitiesReflectRealState(t *testing.T) {
	f := detectNtp(t, &audit.DetectorData{
		IncludeDetails: true,
		DomainControllers: []types.Computer{
			{DN: "CN=DC1,OU=Domain Controllers,DC=example,DC=com", SAMAccountName: "DC1$", Disabled: false},
			{DN: "CN=DC2,OU=Domain Controllers,DC=example,DC=com", SAMAccountName: "DC2$", Disabled: true},
		},
	})
	if len(f.AffectedEntities) != 2 {
		t.Fatalf("expected 2 affected entities, got %d", len(f.AffectedEntities))
	}
	if !f.AffectedEntities[0].Enabled {
		t.Errorf("DC1$ is not disabled in the fixture, expected Enabled=true, got false")
	}
	if f.AffectedEntities[1].Enabled {
		t.Errorf("DC2$ is disabled in the fixture, expected Enabled=false, got true")
	}
}

// TestNtp_IncludeDetailsFalse_NoEntities ensures no entity is ever emitted
// when the caller did not ask for details.
func TestNtp_IncludeDetailsFalse_NoEntities(t *testing.T) {
	f := detectNtp(t, &audit.DetectorData{
		IncludeDetails: false,
		DomainControllers: []types.Computer{
			{DN: "CN=DC1,OU=Domain Controllers,DC=example,DC=com", SAMAccountName: "DC1$", Disabled: false},
			{DN: "CN=DC2,OU=Domain Controllers,DC=example,DC=com", SAMAccountName: "DC2$", Disabled: false},
		},
	})
	if len(f.AffectedEntities) != 0 {
		t.Fatalf("expected no affected entities when IncludeDetails=false, got %d", len(f.AffectedEntities))
	}
}

// TestNtp_DescriptionMatchesDoc couples the runtime finding text to the
// catalog Doc(): a hand-edited Description in Detect() that drifts from
// docs_gen.go must fail here, not slip through as an unnoticed catalog
// mismatch.
func TestNtp_DescriptionMatchesDoc(t *testing.T) {
	d := NewNtpDetector()
	f := detectNtp(t, &audit.DetectorData{
		DomainControllers: []types.Computer{
			{SAMAccountName: "DC1$"},
			{SAMAccountName: "DC2$"},
		},
	})
	doc := d.Doc()
	if f.Description != doc.Description {
		t.Fatalf("Detect() Description drifted from Doc():\nDetect: %q\nDoc:    %q", f.Description, doc.Description)
	}
	if f.Title != doc.Title {
		t.Fatalf("Detect() Title drifted from Doc(): Detect=%q Doc=%q", f.Title, doc.Title)
	}
}
