package audit

import (
	"sort"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit/compliance"
)

// profiles is the registry of named scope presets.
//
// A profile is a static list of categories that get unioned into the scope's
// base set. Empty profile name (or unknown name) means "no preset" — see
// Scope.Resolve for the resulting behaviour.
//
// Adding a new profile here requires a doc update in
// docs/configuration/audit-scope.md.
var profiles = map[string][]DetectorCategory{
	// quick: the cheapest checks that catch the most common AD hygiene issues.
	// Fits a sub-5s spot-check on a small lab.
	"quick": {
		CategoryAccounts,
		CategoryKerberos,
		CategoryPassword,
		CategoryComputers,
	},

	// compliance: only the framework-mapped detectors (CIS, NIST, ANSSI, DISA).
	"compliance": {
		CategoryCompliance,
		CategoryAzureCompliance,
	},

	// pentest: offensive-relevant categories — what a red team would care about.
	"pentest": {
		CategoryKerberos,
		CategoryPermissions,
		CategoryADCS,
		CategoryAttackPaths,
		CategoryAdvanced,
	},
}

// profileCategories returns the categories defined for a profile, or false if
// the profile name is unknown. Lookup is case-insensitive.
func profileCategories(name string) ([]DetectorCategory, bool) {
	cats, ok := profiles[strings.ToLower(strings.TrimSpace(name))]
	return cats, ok
}

// knownProfiles returns a comma-separated list of available profile names,
// useful for error messages.
func knownProfiles() string {
	names := make([]string, 0, len(profiles))
	for n := range profiles {
		names = append(names, n)
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}

// ListProfiles returns the names of all defined profiles, sorted.
func ListProfiles() []string {
	names := make([]string, 0, len(profiles))
	for n := range profiles {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// ProfileCategoriesPublic returns the categories for a public-facing profile
// (used by `audit list` to print the composition).
func ProfileCategoriesPublic(name string) ([]DetectorCategory, bool) {
	return profileCategories(name)
}

// frameworkProfileIDs maps a `compliance-<framework>` profile name to the
// list of detector IDs that have at least one mapping to that framework.
// Returns nil for unknown profiles so the regular category-based path
// still has a chance to match.
//
// Recognised names:
//
//	compliance-anssi      → ANSSI-PA-099 (Active Directory)
//	compliance-anssi-bp039 → ANSSI-BP-039 Windows hardening (LSA Protection, Credential Guard, BitLocker)
//	compliance-anssi-hyg  → ANSSI Guide d'hygiène informatique (40 mesures essentielles)
//	compliance-hds        → HDS v1.1
//	compliance-rgpd       → RGPD art.32
//	compliance-nis2       → NIS2 FR
//	compliance-cis        → CIS Controls v8
//	compliance-nist       → NIST SP 800-53
//	compliance-disa       → DISA STIG
func frameworkProfileIDs(name string) []string {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "compliance-anssi":
		return compliance.DetectorsForFramework(compliance.FrameworkANSSIPA099)
	case "compliance-anssi-bp039":
		return compliance.DetectorsForFramework(compliance.FrameworkANSSIBP039)
	case "compliance-anssi-hyg":
		return compliance.DetectorsForFramework(compliance.FrameworkANSSIGuideHyg)
	case "compliance-hds":
		return compliance.DetectorsForFramework(compliance.FrameworkHDS)
	case "compliance-rgpd":
		return compliance.DetectorsForFramework(compliance.FrameworkRGPD)
	case "compliance-nis2":
		return compliance.DetectorsForFramework(compliance.FrameworkNIS2)
	case "compliance-cis":
		return compliance.DetectorsForFramework(compliance.FrameworkCIS)
	case "compliance-nist":
		return compliance.DetectorsForFramework(compliance.FrameworkNIST)
	case "compliance-disa":
		return compliance.DetectorsForFramework(compliance.FrameworkDISA)
	}
	return nil
}

// FrameworkProfiles returns the framework profile names (used by
// `audit list` to advertise them alongside the category profiles).
func FrameworkProfiles() []string {
	return []string{
		"compliance-anssi", "compliance-anssi-bp039", "compliance-anssi-hyg",
		"compliance-hds", "compliance-rgpd", "compliance-nis2",
		"compliance-cis", "compliance-nist", "compliance-disa",
	}
}
