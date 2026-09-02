package compliance

import "testing"

// dedupedANSSIControls lists every framework-control pair that USED to be
// covered by a dedicated ANSSI detector before the v3.1.21 dedup PR.
// Each entry must remain reachable through at least one mapping in the
// surviving custom detectors — otherwise the corresponding ANSSI control
// would silently drop from "passed/failed" to "not_applicable" in the
// per-framework score, breaking the auditor's trust.
//
// When adding a future dedup, append the (Framework, Control) pair here
// AND add the mapping to the surviving detector. This test catches anyone
// who forgets the second step.
var dedupedANSSIControls = []struct{ framework, control string }{
	// v3.1.21 dedup pass — 18 ANSSI/PA-038/Guide-d'hygiène detectors merged.
	{FrameworkANSSIPA099, "R29"},    // ex-ANSSI_R34_WDIGEST_ENABLED, ex-ANSSI_R34_1_CACHED_LOGONS_TOO_HIGH → WDIGEST_ENABLED, CACHED_LOGONS_EXCESSIVE
	{FrameworkANSSIPA099, "R62"},    // ex-ANSSI_R34_LSA_PROTECTION_OFF, ex-ANSSI_R35_CREDENTIAL_GUARD_OFF → LSA_PROTECTION_DISABLED, CREDENTIAL_GUARD_DISABLED
	{FrameworkANSSIBP039, "R10"},    // ex-ANSSI_R35_CREDENTIAL_GUARD_OFF → CREDENTIAL_GUARD_DISABLED
	{FrameworkANSSIPA099, "R23"},    // ex-ANSSI_R17_SCHEMA_ENTERPRISE_ADMINS_NOT_EMPTY, R19_DNSADMINS, R20_1_BACKUP_OPS, R20_2_PRINT_OPS → custom equivalents
	{FrameworkANSSIPA099, "R44"},    // ex-ANSSI_R2_1_BUILTIN_ADMIN_NOT_RENAMED → M12_DEFAULT_ADMIN_NOT_RENAMED
	{FrameworkANSSIPA099, "R66"},    // ex-ANSSI_R3_1_SMARTCARD_NOT_REQUIRED → ADMIN_NO_SMARTCARD
	{FrameworkANSSIPA099, "R61"},    // ex-ANSSI_R11_ADMINS_NOT_IN_PROTECTED_USERS → NOT_IN_PROTECTED_USERS (already mapped)
	{FrameworkANSSIPA099, "R69"},    // ex-ANSSI_R69_TIER0_SPN_EXPOSED → KERBEROASTING_RISK (Tier 0 split)
	{FrameworkANSSIPA099, "R70"},    // ex-ANSSI_R69_TIER0_SPN_EXPOSED → KERBEROASTING_RISK
	{FrameworkANSSIPA099, "R70-"},   // ex-ANSSI_R69_TIER0_SPN_EXPOSED → KERBEROASTING_RISK
	{FrameworkANSSIPA099, "R52"},    // ex-PA038_ZEROLOGON_ENFORCEMENT_OFF, PA038_HARDENED_UNC → ZEROLOGON_PATCH_ENFORCEMENT, HARDENED_UNC_PATHS_WEAK
	{FrameworkANSSIPA099, "R18"},    // ex-PA038_ZEROLOGON, PA038_HARDENED_UNC, PA038_DEFENDER_ASR → custom equivalents
	{FrameworkANSSIPA099, "R11"},    // ex-PA038_DEFENDER_ASR → DEFENDER_ASR_NOT_CONFIGURED
	{FrameworkANSSIGuideHyg, "M17"}, // ex-PA038_FIREWALL_OUTBOUND → FIREWALL_OUTBOUND_NOT_BLOCKED
	{FrameworkANSSIGuideHyg, "M12"}, // M12 (kept) — also part of the deduped set
	{FrameworkNIS2, "Art.21(2)(e)"}, // ex-PA038_LLMNR, PA038_HARDENED_UNC, PA038_DEFENDER_ASR, PA038_FIREWALL, PA038_ZEROLOGON → custom equivalents
	{FrameworkNIS2, "Art.21(2)(h)"}, // ex-PA038_BITLOCKER → BITLOCKER_NOT_REQUIRED
	{FrameworkNIS2, "Art.21(2)(j)"}, // ex-ANSSI_R3_1_SMARTCARD → ADMIN_NO_SMARTCARD
	{FrameworkRGPD, "art.32(1)(a)"}, // ex-PA038_BITLOCKER → BITLOCKER_NOT_REQUIRED
	{FrameworkHDS, "5.6"},           // ex-ANSSI_R11 → NOT_IN_PROTECTED_USERS (already mapped)
}

// TestNoLossOfANSSIControlCoverageAfterDedup walks the dedup snapshot above
// and verifies that every framework-control pair is still reachable through
// the live mappings table. If a future PR deletes a detector or breaks a
// mapping that was the last one covering one of these controls, this test
// fails with a precise list of orphaned pairs and a recovery hint.
func TestNoLossOfANSSIControlCoverageAfterDedup(t *testing.T) {
	covered := map[string]bool{}
	for _, ms := range mappings {
		for _, m := range ms {
			covered[m.Framework+":"+m.Control] = true
		}
	}
	var lost []string
	for _, want := range dedupedANSSIControls {
		key := want.framework + ":" + want.control
		if !covered[key] {
			lost = append(lost, key)
		}
	}
	if len(lost) > 0 {
		t.Fatalf("Coverage lost on %d ANSSI control(s) after dedup — these were previously emitted by a dedicated detector and must remain reachable via mappings.go:\n  %v\n\nFix: add a mapping from a remaining detector to each lost control.",
			len(lost), lost)
	}
}
