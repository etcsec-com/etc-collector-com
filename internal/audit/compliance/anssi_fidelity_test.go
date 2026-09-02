package compliance

import (
	"strings"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit/compliance/catalogs"
)

// anssiFrameworks lists the framework keys subject to ANSSI fidelity tests.
// Other catalogs (HDS, RGPD, NIS2, NIST, CIS, DISA) are not yet covered —
// they will be added in v3.1.17 after their own external fact-check.
var anssiFrameworks = []string{
	FrameworkANSSIPA099,
	FrameworkANSSIBP039,
	FrameworkANSSIGuideHyg,
}

// TestANSSIControlsHaveOfficialReference enforces that every control in an
// ANSSI catalog is traceable back to its source publication. Required fields:
//   - Catalog.Source     : URL of the official PDF
//   - Catalog.Version    : official version + date
//   - Catalog.FetchedAt  : ISO date of the last external fact-check
//   - ControlSpec.OfficialFR : original French title from the PDF (byte-for-byte)
//
// This test is the contract that lets an ANSSI auditor trust the report:
// every code in the report can be cross-referenced to the official document.
func TestANSSIControlsHaveOfficialReference(t *testing.T) {
	for _, fw := range anssiFrameworks {
		cat := catalogs.Get(fw)
		if cat == nil {
			t.Errorf("catalog %s is not registered", fw)
			continue
		}
		if cat.Source == "" {
			t.Errorf("%s: Catalog.Source must point to the official ANSSI publication", fw)
		}
		if cat.Version == "" {
			t.Errorf("%s: Catalog.Version must include version + publication date", fw)
		}
		if cat.FetchedAt == "" {
			t.Errorf("%s: Catalog.FetchedAt must record the last external fact-check date (YYYY-MM-DD)", fw)
		}
		for _, c := range cat.Controls {
			if c.OfficialFR == "" {
				t.Errorf("%s:%s — OfficialFR is empty (must match the official French title byte-for-byte)", fw, c.Code)
			}
			// Defensive sanity: catch placeholders/TODOs that would slip through.
			if strings.Contains(strings.ToLower(c.OfficialFR), "todo") {
				t.Errorf("%s:%s — OfficialFR looks like a placeholder (%q)", fw, c.Code, c.OfficialFR)
			}
		}
	}
}

// stretchedMappingViolation captures one mapping that was identified as
// inaccurate by external fact-check and explicitly removed in v3.1.16. If
// any of these reappear in mappings.go, this test fails — preventing
// regressions during future refactors.
type stretchedMappingViolation struct {
	Detector  string
	Framework string
	Control   string
	Reason    string
}

// stretchedANSSIBlocklist enumerates every (detector, framework, control)
// triple that was historically present in mappings.go and that v3.1.16
// removed because the detector did not actually verify what the control
// prescribes.
//
// Sources for each ban (cited in the corresponding code comment in
// mappings.go) are the official ANSSI PDFs. See SOURCES.md for the
// fact-check log.
var stretchedANSSIBlocklist = []stretchedMappingViolation{
	// MFA→R66: R66 = "Préserver la préauth. Kerberos pour les comptes de
	// Tier 0", unrelated to MFA.
	{"ANSSI_R3_STRONG_AUTH", FrameworkANSSIPA099, "R66", "R66 is Kerberos pre-auth Tier 0, not MFA"},
	{"MFA_NOT_ENFORCED", FrameworkANSSIPA099, "R66", "R66 is Kerberos pre-auth Tier 0, not MFA"},
	// NIST_IA_5 detector wrongly cross-tagged R66.
	// (R66 stays mapped from ASREP_ROASTING_RISK which is the legitimate use.)

	// Generic password policy → R40 (R40 = Tier 0-specific FGPP only).
	{"ANSSI_R1_PASSWORD_POLICY", FrameworkANSSIPA099, "R40", "R40 is Tier 0-specific FGPP, not generic password policy"},
	{"WEAK_PASSWORD_POLICY", FrameworkANSSIPA099, "R40", "R40 is Tier 0-specific FGPP"},
	{"CIS_PASSWORD_POLICY", FrameworkANSSIPA099, "R40", "R40 is Tier 0-specific FGPP"},
	{"DISA_ACCOUNT_POLICIES", FrameworkANSSIPA099, "R40", "R40 is Tier 0-specific FGPP"},
	{"NIST_IA_5_AUTHENTICATOR", FrameworkANSSIPA099, "R40", "R40 is Tier 0-specific FGPP"},
	{"NIST_IA_5_AUTHENTICATOR", FrameworkANSSIPA099, "R66", "R66 is Kerberos pre-auth Tier 0, not authenticator handling"},

	// Stale/inactive accounts → R29 (R29 = secret dissemination, not lifecycle).
	{"PRIVILEGED_ACCOUNT_STALE", FrameworkANSSIPA099, "R29", "R29 is secret dissemination, not lifecycle"},
	{"VENDOR_ACCOUNT_UNMONITORED", FrameworkANSSIPA099, "R29", "R29 is secret dissemination, not lifecycle"},
	{"ANSSI_R6_INACTIVE_ACCOUNTS", FrameworkANSSIPA099, "R29", "R29 is secret dissemination, not lifecycle"},
	{"ANSSI_R7_STALE_ACCOUNTS_NOT_REMOVED", FrameworkANSSIPA099, "R29", "R29 is secret dissemination, not lifecycle"},
	{"ANSSI_R8_SERVICE_ACCOUNTS_AS_USERS", FrameworkANSSIPA099, "R29", "R29 is secret dissemination, not lifecycle"},
	{"NIST_AC_2_ACCOUNT_MANAGEMENT", FrameworkANSSIPA099, "R29", "R29 is secret dissemination, not lifecycle"},
	{"NOT_IN_PROTECTED_USERS", FrameworkANSSIPA099, "R29", "Use R61 instead"},
	{"ANSSI_R11_ADMINS_NOT_IN_PROTECTED_USERS", FrameworkANSSIPA099, "R29", "Use R61 instead"},

	// Service accounts → R30 (R30 = LAPS local admin pwd specifically).
	{"ANSSI_R9_SERVICE_ACCOUNT_SECRET_ROTATION", FrameworkANSSIPA099, "R30", "R30 is LAPS, not service account rotation; use R33"},

	// Honeypot → R13 (no R-code for deception accounts in PA-099).
	{"NO_HONEYPOT_ACCOUNT", FrameworkANSSIPA099, "R13", "R13 is centralized event logging, not deception"},

	// Generic Tier 0 protocol/permission → R52/R23 (Tier 0-specific only).
	{"PA038_LLMNR_ENABLED", FrameworkANSSIPA099, "R52", "R52 is Tier 0-specific protocol hardening"},
	{"PA038_FIREWALL_OUTBOUND_NOT_RESTRICTED", FrameworkANSSIPA099, "R52", "R52 is Tier 0-specific"},
	{"CIS_NETWORK_SECURITY", FrameworkANSSIPA099, "R52", "R52 is Tier 0-specific"},
	{"CIS_USER_RIGHTS", FrameworkANSSIPA099, "R23", "R23 is Tier 0-specific permissions"},

	// BP-039 fabricated codes (LSA-Protection, BitLocker) — replaced by
	// real codes (R10) where applicable, removed otherwise.
	{"ANSSI_R34_LSA_PROTECTION_OFF", FrameworkANSSIBP039, "LSA-Protection", "fabricated code, not in BP-039 PDF"},
	{"ANSSI_R35_CREDENTIAL_GUARD_OFF", FrameworkANSSIBP039, "Credential-Guard", "fabricated code, use R10"},
	{"PA038_BITLOCKER_NOT_REQUIRED", FrameworkANSSIBP039, "BitLocker", "fabricated code, BitLocker is not in BP-039 catalog"},

	// Guide d'hygiène detector mappings that pointed to wrong measures.
	{"PR001_3_3_ADMIN_NO_DEDICATED_ACCOUNT", FrameworkANSSIGuideHyg, "M9", "wrong measure, use M8"},
	{"PR001_5_1_DC_OS_OBSOLETE", FrameworkANSSIGuideHyg, "M30", "wrong measure (M30 is mobile physical security), use M35"},
}

// TestNoStretchedANSSIMappings ensures the mapping cleanup performed in
// v3.1.16 is not silently regressed by a future commit. Every entry in
// stretchedANSSIBlocklist was confirmed wrong against the official PDFs
// and removed; if it reappears, the test fails with the original reason
// so the contributor can decide whether the cleanup applies to their case.
func TestNoStretchedANSSIMappings(t *testing.T) {
	for _, v := range stretchedANSSIBlocklist {
		ms, ok := mappings[v.Detector]
		if !ok {
			continue // detector removed entirely — fine
		}
		for _, m := range ms {
			if m.Framework == v.Framework && m.Control == v.Control {
				t.Errorf("stretched ANSSI mapping reappeared: %s -> %s:%s (banned in v3.1.16: %s)",
					v.Detector, v.Framework, v.Control, v.Reason)
			}
		}
	}
}
