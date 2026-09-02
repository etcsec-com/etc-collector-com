// Package catalogs holds the authoritative lists of controls for each
// compliance framework supported by ETC Collector.
//
// Each framework has one .go file (anssi_pa099.go, hds_v1_1.go, ...) that
// declares the official controls — code, English title, source section, and
// whether the control is automatable from LDAP/SYSVOL/registry/Graph or
// requires manual verification (organizational, physical, contractual).
//
// The catalogs are the single source of truth for what ETC "knows about".
// The mappings table in mappings.go tags each detector with the official
// control codes it covers. The score-per-framework computation iterates the
// catalog to emit one EvaluatedControl per official control, marking each as
// passed / failed / manual / not_applicable.
//
// IMPORTANT — all user-facing strings (Title, Section, Rationale) MUST be in
// English. The catalogs intentionally avoid French strings even when the
// source publication is in French — translation is performed once at catalog
// load time so the JSON output stays language-consistent across the product.
package catalogs

// ControlSpec describes one official control in a compliance framework.
type ControlSpec struct {
	// Code is the official identifier from the source publication.
	// Examples: "R1" (PA-099), "M14" (Guide d'hygiène), "AC-2" (NIST 800-53),
	// "Art.21(2)(a)" (NIS2), "5.1.4" (HDS v1.1), "V-93195" (DISA STIG),
	// "§1.1" (CIS Controls).
	Code string

	// Title is the English title of the control. For frameworks whose source
	// publication is French (ANSSI), this is a careful technical translation
	// written once and re-used. For English-source frameworks (CIS, NIST, DISA)
	// this is the official title verbatim.
	Title string

	// Section is the chapter or section name from the source publication
	// (English). Used for grouping in dashboards.
	Section string

	// Automatable indicates whether ETC can decide passed/failed automatically
	// from LDAP/SYSVOL/registry/Graph data. False = the control is
	// organizational, contractual, or requires manual verification (interview,
	// physical inspection, document review).
	Automatable bool

	// Rationale is a short English text explaining either:
	//   - WHY a control is not Automatable (e.g. "Organizational process,
	//     not auditable from AD"), or
	//   - WHY a control is not_applicable in a given environment (decided at
	//     audit time, not at catalog declaration time).
	Rationale string

	// === v3.1.16 fidelity-traceability fields ===
	// These are populated for ANSSI catalogs (PA-099, BP-039, Guide d'hygiène)
	// so an ANSSI auditor can cross-reference each control back to the exact
	// source publication. Optional for catalogs whose source language already
	// matches Title (CIS, NIST, DISA — Title is verbatim from the English PDF).

	// OfficialFR is the original French title from the source PDF, kept
	// byte-for-byte. Empty for non-French source documents.
	OfficialFR string
}

// Catalog is the complete list of official controls for one framework.
type Catalog struct {
	// Framework is the JSON framework key (matches mappings.go constants:
	// "ANSSI_PA099", "HDS_v1_1", "RGPD", "NIS2_FR", ...).
	Framework string

	// Source is the canonical URL of the official publication.
	Source string

	// Version is the publication version + date (e.g. "v1.0 (02/10/2023)").
	Version string

	// Controls is the ordered list of official controls. Order follows the
	// publication order so dashboards can render the catalog in the same
	// sequence as the official document.
	Controls []ControlSpec

	// FetchedAt is the ISO date (YYYY-MM-DD) of the last external fact-check
	// of this catalog against its source PDF. Optional but recommended for
	// ANSSI catalogs where fidelity is the contract.
	FetchedAt string
}

// Catalogs is the registry of all frameworks ETC ships with. Populated by
// each framework file's init() (e.g. anssi_pa099.go init() registers
// the PA-099 catalog).
var Catalogs = map[string]*Catalog{}

// Get returns the catalog for a framework, or nil if unknown.
func Get(framework string) *Catalog {
	return Catalogs[framework]
}

// HasControl reports whether the given control code exists in the framework's
// catalog. Used by mappings_test.go to validate that mappings.go does not
// reference unknown controls.
func HasControl(framework, code string) bool {
	cat := Catalogs[framework]
	if cat == nil {
		return false
	}
	for _, c := range cat.Controls {
		if c.Code == code {
			return true
		}
	}
	return false
}

// FindControl returns the ControlSpec for a code, or nil if unknown.
func FindControl(framework, code string) *ControlSpec {
	cat := Catalogs[framework]
	if cat == nil {
		return nil
	}
	for i := range cat.Controls {
		if cat.Controls[i].Code == code {
			return &cat.Controls[i]
		}
	}
	return nil
}

// register adds a catalog to the global registry. Called from each framework
// file's init().
func register(c *Catalog) {
	Catalogs[c.Framework] = c
}
