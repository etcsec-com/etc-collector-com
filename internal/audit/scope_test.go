package audit

import (
	"context"
	"sort"
	"testing"

	"github.com/etcsec-com/etc-collector/pkg/types"
)

// fakeDetector is a minimal Detector for table-driven scope tests.
type fakeDetector struct {
	id  string
	cat DetectorCategory
}

func (f *fakeDetector) ID() string                 { return f.id }
func (f *fakeDetector) Category() DetectorCategory { return f.cat }
func (f *fakeDetector) Doc() DetectorDoc {
	return DetectorDoc{Title: "Fake", Severity: types.SeverityInfo}
}
func (f *fakeDetector) Detect(context.Context, *DetectorData) []types.Finding { return nil }

// buildTestRegistry creates a registry with detectors covering the categories
// referenced by the bundled profiles, so scope+profile tests work in isolation.
func buildTestRegistry(t *testing.T) *Registry {
	t.Helper()
	r := NewRegistry()
	seed := []*fakeDetector{
		{id: "AD_ACCT_1", cat: CategoryAccounts},
		{id: "AD_ACCT_2", cat: CategoryAccounts},
		{id: "AD_KRB_1", cat: CategoryKerberos},
		{id: "AD_KRB_2", cat: CategoryKerberos},
		{id: "AD_PWD_1", cat: CategoryPassword},
		{id: "AD_COMP_1", cat: CategoryComputers},
		{id: "AD_PERM_1", cat: CategoryPermissions},
		{id: "AD_ADCS_1", cat: CategoryADCS},
		{id: "AD_ATTACK_1", cat: CategoryAttackPaths},
		{id: "AD_ADV_1", cat: CategoryAdvanced},
		{id: "AD_NET_1", cat: CategoryNetwork},
		{id: "AD_NET_2", cat: CategoryNetwork},
		{id: "AD_MON_1", cat: CategoryMonitoring},
		{id: "AD_COMPL_1", cat: CategoryCompliance},
		{id: "AZ_COMPL_1", cat: CategoryAzureCompliance},
	}
	for _, d := range seed {
		if err := r.Register(d); err != nil {
			t.Fatalf("register %s: %v", d.id, err)
		}
	}
	return r
}

func sortedIDs(ids []string) []string {
	out := append([]string(nil), ids...)
	sort.Strings(out)
	return out
}

func TestScopeResolve(t *testing.T) {
	reg := buildTestRegistry(t)

	cases := []struct {
		name        string
		scope       Scope
		wantSubset  []string // IDs that MUST be present
		wantAbsent  []string // IDs that MUST be absent
		wantWarning bool
		wantTotal   int // -1 = don't check
	}{
		{
			name:       "empty scope = all detectors",
			scope:      Scope{},
			wantSubset: []string{"AD_ACCT_1", "AD_KRB_1", "AD_NET_1", "AZ_COMPL_1"},
			wantTotal:  15,
		},
		{
			name:       "profile quick = 4 categories",
			scope:      Scope{Profile: "quick"},
			wantSubset: []string{"AD_ACCT_1", "AD_ACCT_2", "AD_KRB_1", "AD_KRB_2", "AD_PWD_1", "AD_COMP_1"},
			wantAbsent: []string{"AD_PERM_1", "AD_ADCS_1", "AD_NET_1", "AZ_COMPL_1"},
			wantTotal:  6,
		},
		{
			name:       "profile pentest",
			scope:      Scope{Profile: "pentest"},
			wantSubset: []string{"AD_KRB_1", "AD_PERM_1", "AD_ADCS_1", "AD_ATTACK_1", "AD_ADV_1"},
			wantAbsent: []string{"AD_ACCT_1", "AD_PWD_1", "AD_NET_1"},
			wantTotal:  6,
		},
		{
			name:       "profile compliance",
			scope:      Scope{Profile: "compliance"},
			wantSubset: []string{"AD_COMPL_1", "AZ_COMPL_1"},
			wantAbsent: []string{"AD_ACCT_1", "AD_KRB_1"},
			wantTotal:  2,
		},
		{
			name:        "unknown profile = warning + empty base",
			scope:       Scope{Profile: "nope"},
			wantWarning: true,
			wantTotal:   15, // falls back to "no preset" → all detectors
		},
		{
			name:       "include single category",
			scope:      Scope{IncludeCategories: []DetectorCategory{CategoryKerberos}},
			wantSubset: []string{"AD_KRB_1", "AD_KRB_2"},
			wantAbsent: []string{"AD_ACCT_1", "AD_NET_1"},
			wantTotal:  2,
		},
		{
			name:       "include category + include detector",
			scope:      Scope{IncludeCategories: []DetectorCategory{CategoryKerberos}, IncludeDetectors: []string{"AD_ADCS_1"}},
			wantSubset: []string{"AD_KRB_1", "AD_KRB_2", "AD_ADCS_1"},
			wantAbsent: []string{"AD_ACCT_1"},
			wantTotal:  3,
		},
		{
			name:       "exclude category from default-all",
			scope:      Scope{ExcludeCategories: []DetectorCategory{CategoryNetwork, CategoryMonitoring}},
			wantAbsent: []string{"AD_NET_1", "AD_NET_2", "AD_MON_1"},
			wantTotal:  12,
		},
		{
			name:       "exclude detector wins over include",
			scope:      Scope{IncludeCategories: []DetectorCategory{CategoryKerberos}, ExcludeDetectors: []string{"AD_KRB_1"}},
			wantSubset: []string{"AD_KRB_2"},
			wantAbsent: []string{"AD_KRB_1", "AD_ACCT_1"},
			wantTotal:  1,
		},
		{
			name:       "profile + exclude category",
			scope:      Scope{Profile: "quick", ExcludeCategories: []DetectorCategory{CategoryPassword}},
			wantSubset: []string{"AD_ACCT_1", "AD_KRB_1", "AD_COMP_1"},
			wantAbsent: []string{"AD_PWD_1"},
			wantTotal:  5,
		},
		{
			name:        "unknown category warning",
			scope:       Scope{IncludeCategories: []DetectorCategory{"nonexistent"}},
			wantWarning: true,
			wantTotal:   15, // empty include = falls back to all
		},
		{
			name:        "unknown detector warning",
			scope:       Scope{IncludeDetectors: []string{"NO_SUCH_ID"}},
			wantWarning: true,
			wantTotal:   15,
		},
		{
			name:       "case-insensitive profile",
			scope:      Scope{Profile: "QUICK"},
			wantSubset: []string{"AD_ACCT_1", "AD_KRB_1"},
			wantTotal:  6,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ids, warnings := tc.scope.Resolve(reg)
			ids = sortedIDs(ids)

			if tc.wantTotal >= 0 && len(ids) != tc.wantTotal {
				t.Errorf("got %d IDs %v, want %d", len(ids), ids, tc.wantTotal)
			}
			present := make(map[string]bool, len(ids))
			for _, id := range ids {
				present[id] = true
			}
			for _, want := range tc.wantSubset {
				if !present[want] {
					t.Errorf("expected ID %q in result, got %v", want, ids)
				}
			}
			for _, unwanted := range tc.wantAbsent {
				if present[unwanted] {
					t.Errorf("unexpected ID %q in result, got %v", unwanted, ids)
				}
			}
			if tc.wantWarning && len(warnings) == 0 {
				t.Errorf("expected at least one warning, got none")
			}
			if !tc.wantWarning && len(warnings) > 0 {
				t.Errorf("expected no warnings, got %v", warnings)
			}
		})
	}
}

func TestScopeIsEmpty(t *testing.T) {
	if !(Scope{}).IsEmpty() {
		t.Fatal("zero-value Scope should be empty")
	}
	if (Scope{Profile: "quick"}).IsEmpty() {
		t.Fatal("Scope with profile should not be empty")
	}
	if (Scope{IncludeDetectors: []string{"X"}}).IsEmpty() {
		t.Fatal("Scope with include detector should not be empty")
	}
}

func TestScopeApplyTo(t *testing.T) {
	reg := buildTestRegistry(t)
	opts := &RunOptions{Categories: []DetectorCategory{CategoryAccounts}}
	s := Scope{Profile: "compliance"}

	warnings := s.ApplyTo(opts, reg)
	if len(warnings) != 0 {
		t.Errorf("unexpected warnings: %v", warnings)
	}
	if len(opts.Categories) != 0 {
		t.Errorf("ApplyTo should clear Categories, got %v", opts.Categories)
	}
	if len(opts.DetectorIDs) != 2 {
		t.Errorf("expected 2 detector IDs (compliance profile), got %d: %v", len(opts.DetectorIDs), opts.DetectorIDs)
	}
}

func TestSelectDetectorsExcludes(t *testing.T) {
	reg := buildTestRegistry(t)
	e := &Engine{registry: reg}

	// Include all kerberos but exclude AD_KRB_2
	opts := RunOptions{
		Categories:       []DetectorCategory{CategoryKerberos},
		ExcludeDetectors: []string{"AD_KRB_2"},
	}
	got := e.selectDetectors(opts)
	if len(got) != 1 || got[0].ID() != "AD_KRB_1" {
		ids := make([]string, len(got))
		for i, d := range got {
			ids[i] = d.ID()
		}
		t.Fatalf("expected [AD_KRB_1], got %v", ids)
	}

	// Default + exclude category
	opts = RunOptions{ExcludeCategories: []DetectorCategory{CategoryNetwork, CategoryMonitoring}}
	got = e.selectDetectors(opts)
	for _, d := range got {
		if d.Category() == CategoryNetwork || d.Category() == CategoryMonitoring {
			t.Errorf("unexpected detector %s in category %s", d.ID(), d.Category())
		}
	}
}
