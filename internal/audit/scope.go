package audit

import (
	"fmt"
	"sort"
)

// Scope describes which detectors should run for an audit.
//
// Three composable axes — categories, detector IDs, and named profiles —
// expressed as include / exclude lists. Resolution rules:
//
//  1. base = registered profile categories (if Profile is set), else all detectors.
//  2. base += IncludeCategories (union)
//  3. base += IncludeDetectors  (union, by ID)
//  4. base -= ExcludeCategories (set difference)
//  5. base -= ExcludeDetectors  (set difference, by ID — last word, always wins)
//
// Empty Scope (zero value) means "run every registered detector".
type Scope struct {
	Profile           string
	IncludeCategories []DetectorCategory
	ExcludeCategories []DetectorCategory
	IncludeDetectors  []string
	ExcludeDetectors  []string
}

// IsEmpty reports whether the scope places no constraint (= run everything).
func (s Scope) IsEmpty() bool {
	return s.Profile == "" &&
		len(s.IncludeCategories) == 0 &&
		len(s.ExcludeCategories) == 0 &&
		len(s.IncludeDetectors) == 0 &&
		len(s.ExcludeDetectors) == 0
}

// Resolve produces the final list of detector IDs to run, plus a list of
// human-readable warnings (unknown profile / category / detector ID).
//
// reg must be the registry that holds the candidate detectors (typically
// audit.DefaultRegistry). The returned IDs are guaranteed to exist in reg.
//
// Warnings are not errors: callers should log them and continue. Returning
// strings keeps the function dependency-free; the daemon and CLI format them
// as appropriate for their respective transports.
func (s Scope) Resolve(reg *Registry) (detectorIDs []string, warnings []string) {
	if reg == nil {
		return nil, []string{"scope: nil registry"}
	}

	// Step 1: build the base set of detector IDs.
	selected := make(map[string]struct{})
	usedBase := false

	if s.Profile != "" {
		// Framework profiles (compliance-anssi/hds/rgpd) resolve to a
		// detector ID list rather than a category list. Try them first.
		if ids := frameworkProfileIDs(s.Profile); ids != nil {
			for _, id := range ids {
				if _, ok := reg.Get(id); ok {
					selected[id] = struct{}{}
				}
			}
			usedBase = true
		} else if profileCats, ok := profileCategories(s.Profile); ok {
			for _, cat := range profileCats {
				for _, d := range reg.GetByCategory(cat) {
					selected[d.ID()] = struct{}{}
				}
			}
			usedBase = true
		} else {
			warnings = append(warnings, fmt.Sprintf("unknown profile %q (using empty base; available: %s)",
				s.Profile, knownProfiles()))
		}
	}

	// Step 2: add IncludeCategories.
	for _, cat := range s.IncludeCategories {
		matches := reg.GetByCategory(cat)
		if len(matches) == 0 {
			warnings = append(warnings, fmt.Sprintf("unknown or empty category %q", string(cat)))
			continue
		}
		for _, d := range matches {
			selected[d.ID()] = struct{}{}
		}
		usedBase = true
	}

	// Step 3: add IncludeDetectors (by ID).
	for _, id := range s.IncludeDetectors {
		if _, ok := reg.Get(id); !ok {
			warnings = append(warnings, fmt.Sprintf("unknown detector ID %q", id))
			continue
		}
		selected[id] = struct{}{}
		usedBase = true
	}

	// Step 4: if no profile or includes were specified, default to all.
	if !usedBase {
		for _, d := range reg.All() {
			selected[d.ID()] = struct{}{}
		}
	}

	// Step 5: subtract ExcludeCategories.
	for _, cat := range s.ExcludeCategories {
		matches := reg.GetByCategory(cat)
		if len(matches) == 0 {
			warnings = append(warnings, fmt.Sprintf("unknown or empty category %q (in excludes)", string(cat)))
			continue
		}
		for _, d := range matches {
			delete(selected, d.ID())
		}
	}

	// Step 6: subtract ExcludeDetectors.
	for _, id := range s.ExcludeDetectors {
		if _, ok := reg.Get(id); !ok {
			warnings = append(warnings, fmt.Sprintf("unknown detector ID %q (in excludes)", id))
			continue
		}
		delete(selected, id)
	}

	detectorIDs = make([]string, 0, len(selected))
	for id := range selected {
		detectorIDs = append(detectorIDs, id)
	}
	sort.Strings(detectorIDs) // deterministic output for tests + logs
	return detectorIDs, warnings
}

// ApplyTo writes the resolved IDs into RunOptions.DetectorIDs and clears the
// other scope fields so the engine bypasses its own (now redundant) filter.
//
// Returns the warnings collected by Resolve so callers can surface them.
func (s Scope) ApplyTo(opts *RunOptions, reg *Registry) []string {
	if opts == nil || s.IsEmpty() {
		return nil
	}
	ids, warnings := s.Resolve(reg)
	opts.DetectorIDs = ids
	// Clear the other selectors — RunOptions.DetectorIDs alone is now the source of truth.
	opts.Categories = nil
	opts.ExcludeCategories = nil
	opts.ExcludeDetectors = nil
	return warnings
}
