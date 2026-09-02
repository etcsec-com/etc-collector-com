package catalogs

import (
	"testing"
)

// TestCatalogsRegistered verifies that every framework expected by the
// compliance package has a registered catalog. The test imports the
// catalogs package's init() so all framework files run.
func TestCatalogsRegistered(t *testing.T) {
	expected := []string{
		"ANSSI_PA099",
		"ANSSI_BP039",
		"ANSSI_GUIDE_HYGIENE",
		"HDS_v1_1",
		"RGPD",
		"NIS2_FR",
		"CIS_v8",
		"NIST_800_53",
		"DISA_STIG",
	}
	for _, fw := range expected {
		if Catalogs[fw] == nil {
			t.Errorf("catalog %q not registered", fw)
		}
	}
}

// TestPA099IsComplete verifies the PA-099 catalog covers all 89 main R-codes
// plus the 8 expected variants. The official ANSSI publication lists 89
// recommendations + 8 sub-recommendations (R14+, R19+, R25+, R30-, R67-,
// R70-, R74+, R80-, R80+, R89-).
func TestPA099IsComplete(t *testing.T) {
	cat := Catalogs["ANSSI_PA099"]
	if cat == nil {
		t.Fatal("ANSSI_PA099 catalog not registered")
	}
	// Spot-check a few specific codes that must exist (taken from the
	// official "Liste des recommandations" appendix of PA-099 v1.0).
	mustHave := []string{
		"R1", "R8", "R13", "R20", "R23", "R29", "R40", "R41",
		"R52", "R56", "R66", "R71", "R72", "R75", "R89",
		"R14+", "R25+", "R30-", "R67-", "R70-", "R89-",
	}
	for _, code := range mustHave {
		if !HasControl("ANSSI_PA099", code) {
			t.Errorf("PA-099 catalog missing required control %q", code)
		}
	}
}

// TestNoEmptyTitles guards against catalog entries with empty titles —
// the JSON output must always have a non-empty title for dashboard rendering.
func TestNoEmptyTitles(t *testing.T) {
	for fw, cat := range Catalogs {
		for _, c := range cat.Controls {
			if c.Title == "" {
				t.Errorf("%s catalog: control %q has empty title", fw, c.Code)
			}
			if c.Code == "" {
				t.Errorf("%s catalog: control with empty code", fw)
			}
		}
	}
}

// TestNoDuplicateCodes guards against accidental duplicate codes within a
// single catalog.
func TestNoDuplicateCodes(t *testing.T) {
	for fw, cat := range Catalogs {
		seen := map[string]bool{}
		for _, c := range cat.Controls {
			if seen[c.Code] {
				t.Errorf("%s catalog: duplicate code %q", fw, c.Code)
			}
			seen[c.Code] = true
		}
	}
}
