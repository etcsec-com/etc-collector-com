// Package compliance owns the cross-framework mapping table and the
// score-per-framework computation. Detectors never reference framework
// names directly — they emit a Finding with their stable Type, and this
// package decorates the resulting findings with ComplianceMapping entries.
//
// The single source of truth is the `mappings` map below: one entry per
// detector ID, listing every official framework control it satisfies.
//
// IMPORTANT — all `Control` values in this file MUST exist in the catalog
// for their `Framework` (see internal/audit/compliance/catalogs/). The
// validation test mappings_test.go enforces this — invalid mappings break
// the build.
//
// Re-mapped in v3.1.14 to use OFFICIAL ANSSI-PA-099 v1.0 R-codes (R1-R89,
// plus sub-recommendations R14+, R19+, R25+, R30-, R67-, R70-, R74+, R80-,
// R80+, R89-) instead of the internal R1-R39 numbering used in v3.1.0–v3.1.13.
package compliance

import (
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// Framework name constants — reused by score_per_framework.go and the
// compliance report templates so a typo causes a compile error rather than
// a silent missing-mapping in the JSON output.
const (
	FrameworkANSSIPA099    = "ANSSI_PA099"         // ANSSI-PA-099 v1.0 (02/10/2023) — Active Directory secure administration
	FrameworkANSSIBP039    = "ANSSI_BP039"         // ANSSI-BP-039 v1.0 (11/2017)    — Windows 10 virtualization-based security
	FrameworkANSSIGuideHyg = "ANSSI_GUIDE_HYGIENE" // ANSSI Guide d'hygiène informatique (42 mesures essentielles)
	FrameworkHDS           = "HDS_v1_1"            // Référentiel HDS v1.1 (Hébergement Données de Santé)
	FrameworkRGPD          = "RGPD"                // RGPD article 32 (sécurité du traitement)
	FrameworkNIS2          = "NIS2_FR"             // NIS2 directive EU 2022/2555, transposition FR loi 2024-449
	FrameworkCIS           = "CIS_v8"              // CIS Controls v8 / CIS Microsoft Windows Server Benchmark
	FrameworkNIST          = "NIST_800_53"         // NIST SP 800-53 Rev.5
	FrameworkDISA          = "DISA_STIG"           // DISA STIG Active Directory Domain V3R3
)

// AllFrameworks lists the frameworks ETC ships with framework-aware
// scoring. Used by `audit list` and the compliance report sub-command.
var AllFrameworks = []string{
	FrameworkANSSIPA099,
	FrameworkANSSIBP039,
	FrameworkANSSIGuideHyg,
	FrameworkHDS, FrameworkRGPD, FrameworkNIS2,
	FrameworkCIS, FrameworkNIST, FrameworkDISA,
}

// mappings is the central detectorID → []ComplianceMapping table.
//
// Re-mapped in v3.1.14 :
//   - ANSSI_PA099 controls now use OFFICIAL R1-R89 + variants (R14+, R19+, etc.)
//     from the published catalog (catalogs/anssi_pa099.go).
//   - ANSSI_GUIDE_HYGIENE uses official M1-M42 codes from the public guide.
//   - All other frameworks use their official codes (see catalogs/).
var mappings = map[string][]types.ComplianceMapping{
	// ────────────────────────────────────────────────────────────────────
	// Password policy — PA-099 R29 (control of reusable secret
	// dissemination). Note: PA-099 R40 (FGPP for Tier 0) was previously
	// over-mapped here; it is now reserved for detectors that specifically
	// verify Tier 0 fine-grained password policies (none today).
	// ────────────────────────────────────────────────────────────────────
	"ANSSI_R1_PASSWORD_POLICY": {
		// PA-099 R40 removed v3.1.16: this detector inspects the domain
		// password policy, not the Tier 0-specific PSO that R40 prescribes.
		{Framework: FrameworkHDS, Control: "5.5"},
		{Framework: FrameworkRGPD, Control: "art.32(1)(a)"},
		{Framework: FrameworkNIST, Control: "IA-5"},
		{Framework: FrameworkCIS, Control: "§1.1"},
		{Framework: FrameworkANSSIGuideHyg, Control: "M10"}, // v3.1.17 cross-tag
	},
	"WEAK_PASSWORD_POLICY": {
		// PA-099 R40 removed v3.1.16: generic password weakness, not a
		// Tier 0-specific PSO check.
		{Framework: FrameworkHDS, Control: "5.5"},
		{Framework: FrameworkNIST, Control: "IA-5"},
		{Framework: FrameworkCIS, Control: "§1.1"},
		{Framework: FrameworkANSSIGuideHyg, Control: "M10"}, // v3.1.17 cross-tag
	},

	// ────────────────────────────────────────────────────────────────────
	// Privileged accounts — PA-099 R1 (privileged access model), R8
	// (segregate admin per tier), R23 (control permissions on Tier 0
	// accounts/groups)
	// ────────────────────────────────────────────────────────────────────
	"ANSSI_R2_PRIVILEGED_ACCOUNTS": {
		{Framework: FrameworkANSSIPA099, Control: "R1"},
		{Framework: FrameworkANSSIPA099, Control: "R2"}, // v3.1.17 — protect each tier proportionately
		{Framework: FrameworkANSSIPA099, Control: "R8"},
		{Framework: FrameworkHDS, Control: "5.6"},
		{Framework: FrameworkNIST, Control: "AC-6"},
	},
	"EXCESSIVE_PRIVILEGED_ACCOUNTS": {
		{Framework: FrameworkANSSIPA099, Control: "R1"},
		{Framework: FrameworkANSSIPA099, Control: "R8"},
		{Framework: FrameworkHDS, Control: "5.6"},
		{Framework: FrameworkNIST, Control: "AC-6"},
		{Framework: FrameworkANSSIGuideHyg, Control: "M5"}, // v3.1.17 — privileged inventory
	},
	"PRIVILEGED_ACCOUNT_STALE": {
		// PA-099 R29 removed v3.1.16: R29 is about controlling the
		// dissemination of reusable secrets, not about account lifecycle.
		// PA-099 has no R-code dedicated to stale/inactive account hygiene.
		{Framework: FrameworkHDS, Control: "5.6"},
	},
	"NOT_IN_PROTECTED_USERS": {
		// PA-099 R29 removed v3.1.16: R61 ("address NTLM/Kerberos secret
		// reusability") is the precise control here, not generic R29.
		{Framework: FrameworkANSSIPA099, Control: "R61"},
	},
	"PRIVILEGED_ACCESS_REVIEW_MISSING": {
		{Framework: FrameworkANSSIPA099, Control: "R1"},
		{Framework: FrameworkHDS, Control: "5.6"},
		{Framework: FrameworkANSSIGuideHyg, Control: "M5"}, // v3.1.17 — privileged inventory
	},
	"VENDOR_ACCOUNT_UNMONITORED": {
		// PA-099 R29 removed v3.1.16: vendor account monitoring is lifecycle,
		// not secret-dissemination control.
		{Framework: FrameworkHDS, Control: "5.6"},
	},

	// ────────────────────────────────────────────────────────────────────
	// Strong authentication / MFA — PA-099 does NOT cover MFA. The previous
	// mapping to R66 was wrong: R66 = "Preserve Kerberos pre-authentication
	// for Tier 0 accounts", unrelated to MFA. Removed in v3.1.16.
	// ────────────────────────────────────────────────────────────────────
	"ANSSI_R3_STRONG_AUTH": {
		// PA-099 R66 removed v3.1.16 — Kerberos pre-auth is not MFA.
		{Framework: FrameworkHDS, Control: "5.1.4"},
		{Framework: FrameworkRGPD, Control: "art.32(1)(b)"},
		{Framework: FrameworkNIST, Control: "IA-2"},
		{Framework: FrameworkNIS2, Control: "Art.21(2)(j)"},
		{Framework: FrameworkANSSIGuideHyg, Control: "M13"}, // v3.1.17 — strong auth
	},
	"MFA_NOT_ENFORCED": {
		// PA-099 R66 removed v3.1.16 — same reason as ANSSI_R3_STRONG_AUTH.
		{Framework: FrameworkHDS, Control: "5.1.4"},
		{Framework: FrameworkNIS2, Control: "Art.21(2)(j)"},
		{Framework: FrameworkANSSIGuideHyg, Control: "M13"}, // v3.1.17 — strong auth
	},

	// ────────────────────────────────────────────────────────────────────
	// Logging & audit — PA-099 R13 (log and centralize security events)
	// ────────────────────────────────────────────────────────────────────
	"ANSSI_R4_LOGGING": {
		{Framework: FrameworkANSSIPA099, Control: "R13"},
		{Framework: FrameworkHDS, Control: "5.4"},
		{Framework: FrameworkRGPD, Control: "art.32(1)(b)"},
		{Framework: FrameworkNIST, Control: "AU-2"},
		{Framework: FrameworkANSSIGuideHyg, Control: "M36"}, // v3.1.17 — logs activated
	},
	"AUDIT_LOG_RETENTION_SHORT": {
		{Framework: FrameworkANSSIPA099, Control: "R13"},
		{Framework: FrameworkHDS, Control: "5.4"},
		{Framework: FrameworkNIST, Control: "AU-4"},
		{Framework: FrameworkANSSIGuideHyg, Control: "M36"}, // v3.1.17 — logs activated
	},
	"NO_HONEYPOT_ACCOUNT": {
		// PA-099 R13 removed v3.1.16: honeypot is a deception/detection
		// technique, not centralized event logging. PA-099 has no R-code
		// dedicated to deception accounts.
		{Framework: FrameworkRGPD, Control: "art.32(1)(b)"},
	},

	// ────────────────────────────────────────────────────────────────────
	// Tier model / segregation — PA-099 R7 (categorize), R8 (segregate),
	// R58 (Tier 0 OU), R59 (restrict policies on Tier 0 OU)
	// ────────────────────────────────────────────────────────────────────
	"ANSSI_R5_SEGREGATION": {
		{Framework: FrameworkANSSIPA099, Control: "R7"},
		{Framework: FrameworkANSSIPA099, Control: "R8"},
		{Framework: FrameworkHDS, Control: "5.9"},
	},
	"ANSSI_R15_TIER_MODEL_VIOLATION": {
		{Framework: FrameworkANSSIPA099, Control: "R8"},
		{Framework: FrameworkANSSIPA099, Control: "R10"}, // v3.1.17 — minimize tier exposure
		{Framework: FrameworkANSSIPA099, Control: "R58"},
		{Framework: FrameworkHDS, Control: "5.9"},
		{Framework: FrameworkNIST, Control: "AC-5"},
	},

	// ────────────────────────────────────────────────────────────────────
	// Account lifecycle — PA-099 has NO R-code dedicated to lifecycle
	// (R29 covers dissemination of reusable secrets, not joiner-leaver).
	// Mappings preserved on the cross-framework controls (NIST AC-2 etc).
	// ────────────────────────────────────────────────────────────────────
	"ANSSI_R6_INACTIVE_ACCOUNTS": {
		// PA-099 R29 removed v3.1.16: lifecycle, not secret dissemination.
		{Framework: FrameworkHDS, Control: "5.6"},
		{Framework: FrameworkNIST, Control: "AC-2"},
	},
	"ANSSI_R7_STALE_ACCOUNTS_NOT_REMOVED": {
		// PA-099 R29 removed v3.1.16.
		{Framework: FrameworkNIST, Control: "AC-2"},
	},
	"ANSSI_R8_SERVICE_ACCOUNTS_AS_USERS": {
		// PA-099 R29 removed v3.1.16.
		{Framework: FrameworkHDS, Control: "5.6"},
	},
	"ANSSI_R9_SERVICE_ACCOUNT_SECRET_ROTATION": {
		// PA-099 R30 removed v3.1.16: R30 is LAPS-specific (local admin
		// password rotation). R33 ("secrets of scheduled tasks and Windows
		// services") is the precise control for service-account rotation.
		{Framework: FrameworkANSSIPA099, Control: "R33"},
		{Framework: FrameworkHDS, Control: "5.5"},
		{Framework: FrameworkRGPD, Control: "art.32(1)(a)"},
		{Framework: FrameworkNIST, Control: "IA-5"},
	},
	"STALE_ACCOUNT": {
		{Framework: FrameworkNIST, Control: "AC-2"},
	},

	// ────────────────────────────────────────────────────────────────────
	// Protected Users / NTLM hash protection — PA-099 R29 + R61
	// ────────────────────────────────────────────────────────────────────
	// v3.1.21 dedup — ANSSI_R11_ADMINS_NOT_IN_PROTECTED_USERS removed (NOT_IN_PROTECTED_USERS already maps to R61 + HDS 5.6).

	// ────────────────────────────────────────────────────────────────────
	// AD control paths / DCSync / AdminSDHolder — PA-099 R20 (control paths
	// to system containers), R21 (preserve permissions), R22 (control paths
	// to accounts/groups), R23 (control permissions on Tier 0 accounts)
	// ────────────────────────────────────────────────────────────────────
	"DCSYNC_CAPABLE": {
		{Framework: FrameworkANSSIPA099, Control: "R6"},  // v3.1.17 — analyze attack paths
		{Framework: FrameworkANSSIPA099, Control: "R12"}, // v3.1.19 — fine-grained delegation
		{Framework: FrameworkANSSIPA099, Control: "R22", Severity: "critical"},
		{Framework: FrameworkANSSIPA099, Control: "R23", Severity: "critical"},
		{Framework: FrameworkHDS, Control: "5.6"},
		{Framework: FrameworkNIST, Control: "AC-6"},
		{Framework: FrameworkNIS2, Control: "Art.21(2)(i)"},
		{Framework: FrameworkANSSIGuideHyg, Control: "M9"}, // v3.1.17 — right rights
	},
	"ADMIN_SD_HOLDER_MODIFIED": {
		{Framework: FrameworkANSSIPA099, Control: "R12"}, // v3.1.19 — fine-grained delegation (AdminSDHolder is the canonical mass-delegation surface)
		{Framework: FrameworkANSSIPA099, Control: "R20", Severity: "critical"},
		{Framework: FrameworkANSSIPA099, Control: "R21", Severity: "critical"},
		{Framework: FrameworkNIS2, Control: "Art.21(2)(i)"},
		{Framework: FrameworkANSSIGuideHyg, Control: "M9"}, // v3.1.17 — right rights
	},

	// ────────────────────────────────────────────────────────────────────
	// Kerberos delegation — PA-099 R65 (address Kerberos delegation risks)
	// ────────────────────────────────────────────────────────────────────
	"UNCONSTRAINED_DELEGATION": {
		{Framework: FrameworkANSSIPA099, Control: "R65", Severity: "critical"},
	},
	"ANSSI_R14_RBCD_AUDIT": {
		{Framework: FrameworkANSSIPA099, Control: "R65"},
		{Framework: FrameworkNIS2, Control: "Art.21(2)(i)"},
	},

	// ────────────────────────────────────────────────────────────────────
	// Kerberos pre-auth (AS-REP roasting) — PA-099 R66 + R67
	// ────────────────────────────────────────────────────────────────────
	"ASREP_ROASTING_RISK": {
		{Framework: FrameworkANSSIPA099, Control: "R66"},
		{Framework: FrameworkANSSIPA099, Control: "R67"},
		{Framework: FrameworkANSSIPA099, Control: "R67-"}, // v3.1.17 — reduce reusable secrets scope
		{Framework: FrameworkNIS2, Control: "Art.21(2)(j)"},
	},

	// ────────────────────────────────────────────────────────────────────
	// Crypto / signing — PA-099 R52 (secure communication protocols),
	// R75 (LDAP NTLM relay), R76 (SMB NTLM relay)
	// ────────────────────────────────────────────────────────────────────
	"SMB_SIGNING_DISABLED": {
		{Framework: FrameworkANSSIPA099, Control: "R52"},
		{Framework: FrameworkANSSIPA099, Control: "R76"},
		{Framework: FrameworkHDS, Control: "5.2"},
		{Framework: FrameworkRGPD, Control: "art.32(1)(a)"},
		{Framework: FrameworkNIS2, Control: "Art.21(2)(h)"},
		{Framework: FrameworkCIS, Control: "§2.3"},
		{Framework: FrameworkANSSIGuideHyg, Control: "M21"}, // v3.1.17 — secure protocols
	},
	"LDAP_CHANNEL_BINDING_DISABLED": {
		{Framework: FrameworkANSSIPA099, Control: "R75"},
		{Framework: FrameworkHDS, Control: "5.2"},
		{Framework: FrameworkNIS2, Control: "Art.21(2)(h)"},
		{Framework: FrameworkCIS, Control: "§2.3"},
	},

	// ────────────────────────────────────────────────────────────────────
	// Weak crypto / NTLM — PA-099 R67/R70 (was R52 until T_114), R71, R72
	// ────────────────────────────────────────────────────────────────────
	// R52 removed v3.1.22 (T_114): R52 (p.67, "Securiser les protocoles de
	// communication reseau utilises par les ressources du Tier 0") is about
	// network communication protocols (HTTP, SMB, mutual-auth encapsulation)
	// — it never mentions Kerberos ticket encryption types, RC4, DES, or AES.
	// T_103 had already flagged this as "plausible mais imprecis" without
	// finding a closer code. R67 (p.92) and R70 (p.94) both literally name
	// the exact mechanism this detector reads, as one of the three
	// conditions for an accepted no-preauth/SPN-exposed exception: "seuls
	// des chiffrements Kerberos par AES (128 ou 256 bits) sont autorises...
	// soit par desactivation des algorithmes Kerberos DES-CBC-* et
	// RC4-HMAC-* dans le domaine AD". Kept as two citations (both R-codes
	// state the identical AES-vs-RC4/DES condition) despite them being
	// embedded conditions on a narrower account population (no-preauth /
	// SPN-exposed) rather than a standalone "disable RC4/DES everywhere"
	// rule — still far more precise than R52's zero textual connection.
	"WEAK_ENCRYPTION_DES": {
		{Framework: FrameworkANSSIPA099, Control: "R67"},
		{Framework: FrameworkANSSIPA099, Control: "R70"},
		{Framework: FrameworkRGPD, Control: "art.32(1)(a)"},
		{Framework: FrameworkNIS2, Control: "Art.21(2)(h)"},
		{Framework: FrameworkANSSIGuideHyg, Control: "M21"}, // v3.1.17
	},
	"WEAK_ENCRYPTION_RC4": {
		{Framework: FrameworkRGPD, Control: "art.32(1)(a)"},
		{Framework: FrameworkANSSIPA099, Control: "R67"},
		{Framework: FrameworkANSSIPA099, Control: "R70"},
		{Framework: FrameworkNIS2, Control: "Art.21(2)(h)"},
		{Framework: FrameworkANSSIGuideHyg, Control: "M21"}, // v3.1.17
	},
	// R72 verified v3.1.24 (T_118), neighbor check after the RESTRICT_REMOTE_SAM/R72
	// fix (T_117): R72 (p.98) Listing 13's FIRST parameter is "Niveau
	// d'authentification LAN Manager: ... refuser LM et NTLM" — exactly
	// LmCompatibilityLevel>=5, exactly what this detector reads. Description
	// below ("Level 5 (Send NTLMv2 response only, refuse LM & NTLM)") is a
	// verbatim translation of R72's own listing. Textually correct, kept.
	"NTLMV1_ALLOWED": {
		{Framework: FrameworkANSSIPA099, Control: "R71"},
		{Framework: FrameworkANSSIPA099, Control: "R72"},
		{Framework: FrameworkRGPD, Control: "art.32(1)(a)"},
		{Framework: FrameworkNIS2, Control: "Art.21(2)(h)"},
		{Framework: FrameworkCIS, Control: "§2.3"},
		{Framework: FrameworkANSSIGuideHyg, Control: "M21"}, // v3.1.17
	},
	"SMB_V1_ENABLED": {
		{Framework: FrameworkANSSIPA099, Control: "R52"},
		{Framework: FrameworkNIS2, Control: "Art.21(2)(e)"},
		{Framework: FrameworkANSSIGuideHyg, Control: "M21"}, // v3.1.17
	},

	// ────────────────────────────────────────────────────────────────────
	// LM hash — PA-099 R72 (NTLM hardening)
	// ────────────────────────────────────────────────────────────────────
	// R72 verified v3.1.24 (T_118): the ID/title say "LM hash storage", but
	// r16_to_r27_privileges_crypto.go's R23LMHashStorageDetector actually
	// reads LmCompatibilityLevel>=5 as a proxy (own code comment: "Without
	// explicit NoLMHash parsing, fall back to LmCompatibilityLevel"), same
	// field NTLMV1_ALLOWED reads (check-registry.yml's BP039_VBS_OFF entry
	// independently notes this exact key reuse, T_112). R72 (p.98) Listing
	// 13 mandates that same LAN-Manager-auth-level setting AND its own
	// paragraph explicitly proscribes "l'utilisation des protocoles LM" —
	// the citation matches what the code tests, not what the detector's
	// name implies (NoLMHash, a distinct setting R72 never mentions — zero
	// hits for "NoLMHash"/"hash LM"/"SAM" anywhere in the 166-page PDF,
	// same exhaustive search as T_117's RESTRICT_REMOTE_SAM/R72 removal).
	// Kept because it cites the real signal; the name-vs-implementation gap
	// is a detector-design note, not a mapping defect — out of scope here.
	"ANSSI_R23_LM_HASH_NOT_DISABLED": {
		{Framework: FrameworkANSSIPA099, Control: "R72"},
		{Framework: FrameworkRGPD, Control: "art.32(1)(a)"},
		{Framework: FrameworkNIS2, Control: "Art.21(2)(h)"},
		{Framework: FrameworkCIS, Control: "§1.1"},
		{Framework: FrameworkANSSIGuideHyg, Control: "M11"}, // v3.1.17 — protect stored passwords
	},

	// ────────────────────────────────────────────────────────────────────
	// Trusts — PA-099 R24 (harden outgoing extra-forest trusts), R25+
	// (selective auth on outgoing trusts), R26 (forbid Kerberos delegation
	// across incoming trusts)
	// ────────────────────────────────────────────────────────────────────
	"ANSSI_R29_TRUST_SID_FILTERING_OFF": {
		{Framework: FrameworkANSSIPA099, Control: "R24"},
	},
	"ANSSI_R29_1_FOREST_TRUST_NO_SELECTIVE_AUTH": {
		{Framework: FrameworkANSSIPA099, Control: "R25+"},
	},
	"ANSSI_R30_TRUST_SELECTIVE_AUTH_OFF": {
		{Framework: FrameworkANSSIPA099, Control: "R25+"},
	},
	"ANSSI_R31_TRUST_TGT_DELEGATION": {
		{Framework: FrameworkANSSIPA099, Control: "R26"},
	},
	"ANSSI_R32_TRUST_RC4_ALLOWED": {
		{Framework: FrameworkANSSIPA099, Control: "R52"},
		{Framework: FrameworkRGPD, Control: "art.32(1)(a)"},
	},
	"ANSSI_R33_EXTERNAL_TRUST_PERMISSIVE": {
		{Framework: FrameworkANSSIPA099, Control: "R24"},
	},

	// ────────────────────────────────────────────────────────────────────
	// Tier 0 group control — PA-099 R23 (control permissions on Tier 0
	// accounts/groups)
	// ────────────────────────────────────────────────────────────────────
	// v3.1.21 dedup — ANSSI_R17_SCHEMA_ENTERPRISE_ADMINS_NOT_EMPTY removed (SCHEMA_ADMINS_NOT_EMPTY mapping added below).
	"ANSSI_R18_GPCO_NOT_MINIMAL": {
		{Framework: FrameworkANSSIPA099, Control: "R23"},
	},
	// v3.1.21 dedup — ANSSI_R19_DNSADMINS_NOT_EMPTY removed (DNS_ADMINS_MEMBER mapping added below).
	"ACCOUNT_OPERATORS_MEMBER": {{Framework: FrameworkANSSIPA099, Control: "R23"}, {Framework: FrameworkCIS, Control: "§2.2"}},
	"SERVER_OPERATORS_MEMBER":  {{Framework: FrameworkANSSIPA099, Control: "R23"}, {Framework: FrameworkCIS, Control: "§2.2"}},
	"PRINT_OPERATORS_MEMBER":   {{Framework: FrameworkANSSIPA099, Control: "R23"}, {Framework: FrameworkCIS, Control: "§2.2"}},
	"BACKUP_OPERATORS_MEMBER":  {{Framework: FrameworkANSSIPA099, Control: "R23"}, {Framework: FrameworkCIS, Control: "§2.2"}},
	// v3.1.21 dedup — ANSSI_R20_1/R20_2_*_OPERATORS_MEMBER removed (custom IDs already mapped to R23).

	// ────────────────────────────────────────────────────────────────────
	// Sub-recommendations from PA-099
	// ────────────────────────────────────────────────────────────────────
	// v3.1.21 dedup — ANSSI_R2_1_BUILTIN_ADMIN_NOT_RENAMED removed (M12 maps to both M12 + R44).
	"ANSSI_R2_2_GUEST_ENABLED": {
		// PA-099 R29 removed T_113: R29 (p.46) = "Maîtriser la dissémination
		// de toute forme de secret d'authentification réutilisable" — a
		// Tier-based scoping rule for reusable credentials (passwords, NTLM
		// hashes, Kerberos secrets, cert private keys, SSH keys), nothing to
		// do with the built-in Guest account's enabled state. Full-text
		// search of the published PDF (ANSSI-PA-099 v1.0, 02/10/2023) for
		// "Guest"/"invité" finds zero occurrences describing the account —
		// PA-099 has no R-code for it. NIST AC-2 (Account Management)
		// already covers this correctly on its own.
		{Framework: FrameworkNIST, Control: "AC-2"},
	},
	// v3.1.21 dedup — ANSSI_R3_1_SMARTCARD_NOT_REQUIRED removed (ADMIN_NO_SMARTCARD mapping added below).
	"ANSSI_R12_1_FORCE_PWD_RESET_PRIVS":       {{Framework: FrameworkANSSIPA099, Control: "R23"}, {Framework: FrameworkHDS, Control: "5.6"}},
	"ANSSI_R12_2_USER_RESTRICTIONS_PRIVS":     {{Framework: FrameworkANSSIPA099, Control: "R23"}, {Framework: FrameworkHDS, Control: "5.6"}},
	"ANSSI_R15_1_RODC_NO_ALLOWED_REPL":        {{Framework: FrameworkANSSIPA099, Control: "R56"}, {Framework: FrameworkANSSIPA099, Control: "R57"}},
	"ANSSI_R15_2_T0_ADMIN_REPLICATED_TO_RODC": {{Framework: FrameworkANSSIPA099, Control: "R56", Severity: "critical"}, {Framework: FrameworkANSSIPA099, Control: "R57", Severity: "critical"}},
	// v3.1.21 dedup — ANSSI_R34_1_CACHED_LOGONS_TOO_HIGH removed (CACHED_LOGONS_EXCESSIVE mapping added below).
	// R72 removed v3.1.23 (T_117): R72 (p.98) is exclusively "Durcir la
	// configuration de NTLM" (NTLMv2 + 128-bit encryption, Listing 13 —
	// LAN Manager auth level, NTLM SSP minimum session security). Zero
	// textual connection to RestrictRemoteSAM/SAMR enumeration hardening.
	// Exhaustive search of the full published PDF (166 pages) for "SAM",
	// "SAMR", "RestrictRemoteSAM", "gestionnaire de comptes" finds zero
	// hits — PA-099 does not cover SAM remote-enumeration hardening under
	// any R-code. Same defect class as PA038_NET_SESSION_HARDENING_OFF/R72
	// (T_114) and WEAK_ENCRYPTION_RC4/R52 (T_114). R18 (general Tier 0
	// security-baseline hardening — RestrictRemoteSAM is exactly this kind
	// of Microsoft security-baseline registry setting) kept as the only
	// defensible citation, same reasoning as the T_114 precedent.
	"ANSSI_R34_2_RESTRICT_REMOTE_SAM_OFF": {{Framework: FrameworkANSSIPA099, Control: "R18"}},
	"ANSSI_R36_1_LAPS_EXPIRY_TOO_LONG":    {{Framework: FrameworkANSSIPA099, Control: "R30"}},

	// ────────────────────────────────────────────────────────────────────
	// krbtgt / kerberos armoring — PA-099 R41 (krbtgt rotation), R68
	// (Kerberos armoring on Tier 0)
	// ────────────────────────────────────────────────────────────────────
	"ANSSI_R28_KRBTGT_NOT_ROTATED": {
		{Framework: FrameworkANSSIPA099, Control: "R41", Severity: "critical"},
		{Framework: FrameworkNIS2, Control: "Art.21(2)(c)"},
	},
	"ANSSI_R27_KERBEROS_PREAUTH_NOT_FAST": {
		{Framework: FrameworkANSSIPA099, Control: "R68"},
	},

	// ────────────────────────────────────────────────────────────────────
	// LSA Protection / Credential Guard — PA-099 R62 (Credential Guard
	// as defense in depth) + BP-039 controls
	// ────────────────────────────────────────────────────────────────────
	// v3.1.21 dedup — ANSSI_R34_LSA_PROTECTION_OFF, ANSSI_R34_WDIGEST_ENABLED,
	// and ANSSI_R35_CREDENTIAL_GUARD_OFF removed (custom LSA_PROTECTION_DISABLED,
	// WDIGEST_ENABLED, CREDENTIAL_GUARD_DISABLED mappings added below).

	// ────────────────────────────────────────────────────────────────────
	// LAPS / local admin password rotation — PA-099 R30 (rotate local
	// admin passwords)
	// ────────────────────────────────────────────────────────────────────
	"LAPS_NOT_DEPLOYED": {
		{Framework: FrameworkANSSIPA099, Control: "R30"},
		{Framework: FrameworkANSSIPA099, Control: "R30-"}, // v3.1.17 — manual diversification mitigation
		{Framework: FrameworkANSSIBP039, Control: "R12"},  // v3.1.17 — local admin password mgmt
	},

	// ────────────────────────────────────────────────────────────────────
	// AppLocker / WDAC — PA-099 R11 (system/software hardening)
	// ────────────────────────────────────────────────────────────────────
	"ANSSI_R37_APPLOCKER_NOT_ENFORCED": {
		{Framework: FrameworkANSSIPA099, Control: "R11"},
	},

	// ────────────────────────────────────────────────────────────────────
	// Advanced audit policy — PA-099 R13 (log and centralize)
	// ────────────────────────────────────────────────────────────────────
	"ANSSI_R38_ADVANCED_AUDIT_NOT_ENABLED": {
		{Framework: FrameworkANSSIPA099, Control: "R13"},
		{Framework: FrameworkHDS, Control: "5.4"},
		{Framework: FrameworkNIST, Control: "AU-2"},
		{Framework: FrameworkANSSIGuideHyg, Control: "M36"}, // v3.1.17 — logs activated
	},
	"ANSSI_R39_SECURITY_LOG_TOO_SMALL": {
		{Framework: FrameworkANSSIPA099, Control: "R13"},
		{Framework: FrameworkHDS, Control: "5.4"},
		{Framework: FrameworkNIST, Control: "AU-4"},
	},

	// ────────────────────────────────────────────────────────────────────
	// Backup / DR — RGPD art.32(1)(c), HDS 5.7/5.8, NIS2 Art.21(2)(c)
	// ────────────────────────────────────────────────────────────────────
	"BACKUP_AD_NOT_VERIFIED": {
		{Framework: FrameworkHDS, Control: "5.7"},
		{Framework: FrameworkRGPD, Control: "art.32(1)(c)"},
		{Framework: FrameworkNIS2, Control: "Art.21(2)(c)"},
		{Framework: FrameworkCIS, Control: "CIS-11"},
	},
	"AD_RECYCLE_BIN_DISABLED": {
		{Framework: FrameworkRGPD, Control: "art.32(1)(c)"},
		{Framework: FrameworkHDS, Control: "5.7"},
	},
	"NO_OFFLINE_BACKUP": {
		{Framework: FrameworkRGPD, Control: "art.32(1)(c)"},
		{Framework: FrameworkHDS, Control: "5.7"},
		{Framework: FrameworkCIS, Control: "CIS-11"},
	},

	// ────────────────────────────────────────────────────────────────────
	// Other industry detectors
	// ────────────────────────────────────────────────────────────────────
	"ENCRYPTION_AT_REST_DISABLED": {
		{Framework: FrameworkHDS, Control: "5.3"},
		{Framework: FrameworkRGPD, Control: "art.32(1)(a)"},
	},
	"DATA_CLASSIFICATION_MISSING": {
		{Framework: FrameworkHDS, Control: "5.10"},
		{Framework: FrameworkRGPD, Control: "art.32(1)(a)"},
	},
	"CHANGE_MANAGEMENT_BYPASS": {
		{Framework: FrameworkHDS, Control: "5.4"},
	},

	// ────────────────────────────────────────────────────────────────────
	// HDS native detectors
	// ────────────────────────────────────────────────────────────────────
	"HDS_5_1_4_STRONG_AUTH": {
		{Framework: FrameworkHDS, Control: "5.1.4"},
		{Framework: FrameworkRGPD, Control: "art.32(1)(b)"},
	},
	"HDS_5_2_TLS_NOT_ENFORCED": {
		{Framework: FrameworkHDS, Control: "5.2"},
		{Framework: FrameworkRGPD, Control: "art.32(1)(a)"},
	},
	"HDS_5_4_LOG_ACCESS_TO_HEALTH_DATA": {
		{Framework: FrameworkHDS, Control: "5.4"},
		{Framework: FrameworkRGPD, Control: "art.32(1)(b)"},
	},
	"HDS_5_8_DR_PLAN_MISSING": {
		{Framework: FrameworkHDS, Control: "5.8"},
		{Framework: FrameworkRGPD, Control: "art.32(1)(c)"},
	},
	"HDS_5_14_PENTEST_CADENCE": {
		{Framework: FrameworkHDS, Control: "5.14"},
		{Framework: FrameworkRGPD, Control: "art.32(1)(d)"},
	},

	// ────────────────────────────────────────────────────────────────────
	// PA-038 family — Windows hardening detectors. Tagged on PA-099 R52
	// (secure communication protocols) for network-related items, R29
	// (control reusable secrets) for credential-related items, and BP-039
	// where applicable.
	// ────────────────────────────────────────────────────────────────────
	"PA038_RDP_NLA_NOT_REQUIRED": {
		{Framework: FrameworkANSSIPA099, Control: "R18"}, // v3.1.19 — security baselines Tier 0
		{Framework: FrameworkANSSIPA099, Control: "R52"},
		{Framework: FrameworkNIS2, Control: "Art.21(2)(e)"},
	},
	"PA038_RDP_SECURITY_LAYER_WEAK": {
		{Framework: FrameworkANSSIPA099, Control: "R52"},
		{Framework: FrameworkNIS2, Control: "Art.21(2)(e)"},
	},
	"PA038_PS_SCRIPTBLOCK_LOGGING_OFF": {
		{Framework: FrameworkANSSIPA099, Control: "R13"},
		{Framework: FrameworkANSSIPA099, Control: "R18"}, // v3.1.19 — security baselines Tier 0
		{Framework: FrameworkNIS2, Control: "Art.21(2)(b)"},
	},
	"PA038_PS_MODULE_LOGGING_OFF": {
		{Framework: FrameworkANSSIPA099, Control: "R13"},
		{Framework: FrameworkANSSIPA099, Control: "R18"}, // v3.1.19
		{Framework: FrameworkNIS2, Control: "Art.21(2)(b)"},
	},
	"PA038_PS_TRANSCRIPTION_OFF": {
		{Framework: FrameworkANSSIPA099, Control: "R13"},
		{Framework: FrameworkANSSIPA099, Control: "R18"}, // v3.1.19
		{Framework: FrameworkNIS2, Control: "Art.21(2)(b)"},
	},
	// v3.1.21 dedup — PA038_LLMNR_ENABLED, PA038_HARDENED_UNC_PATHS_MISSING,
	// PA038_BITLOCKER_NOT_REQUIRED, PA038_DEFENDER_ASR_NOT_ENABLED,
	// PA038_FIREWALL_OUTBOUND_NOT_RESTRICTED removed (custom mappings added below).
	"PA038_WSUS_NOT_CONFIGURED": {
		{Framework: FrameworkANSSIPA099, Control: "R51"},
		{Framework: FrameworkNIS2, Control: "Art.21(2)(e)"},
	},
	"PA038_POINT_AND_PRINT_ELEVATION_OFF": {
		{Framework: FrameworkANSSIPA099, Control: "R11"},
		{Framework: FrameworkANSSIPA099, Control: "R18"}, // v3.1.19
		{Framework: FrameworkNIS2, Control: "Art.21(2)(e)"},
	},
	// v3.1.21 dedup — PA038_ZEROLOGON_ENFORCEMENT_OFF removed (ZEROLOGON_PATCH_ENFORCEMENT mapping added below).
	// R72 removed v3.1.22 (T_114): R72 (p.98) is exclusively "Durcir la
	// configuration de NTLM" — its own scope (Listing 13) is three
	// registry settings (LAN Manager auth level, NTLM SSP minimum session
	// security client/server), none of which is SrvsvcSessionInfo /
	// NetCease session-enumeration hardening. Zero textual connection,
	// same defect class as WEAK_ENCRYPTION_RC4/R52 (T_114) and
	// GUEST_ENABLED/R29 (T_113). Exhaustive search of the published PDF
	// for "énumération"/"NetSessionEnum"/"sessions actives" finds nothing
	// — PA-099 does not cover NetCease-style session-enumeration
	// hardening at all. R18 (general Tier 0 system/software hardening
	// baseline) is kept as the only defensible citation.
	"PA038_NET_SESSION_HARDENING_OFF": {
		{Framework: FrameworkANSSIPA099, Control: "R18"}, // v3.1.19
		{Framework: FrameworkNIS2, Control: "Art.21(2)(i)"},
	},

	// ────────────────────────────────────────────────────────────────────
	// PR-001 detectors (legacy detector IDs; tagged on PA-099 equivalents)
	// ────────────────────────────────────────────────────────────────────
	"PR001_3_3_ADMIN_NO_DEDICATED_ACCOUNT": {
		{Framework: FrameworkANSSIPA099, Control: "R8"},
		// Guide d'hygiène M8 = "Identifier nommément chaque personne ... et
		// distinguer les rôles utilisateur/administrateur" — fit bien plus
		// précis que l'ancien M9 (= attribuer les bons droits sur ressources
		// sensibles, sujet différent).
		{Framework: FrameworkANSSIGuideHyg, Control: "M8"},
	},
	"PR001_5_1_DC_OS_OBSOLETE": {
		{Framework: FrameworkANSSIPA099, Control: "R16"},
		// Guide d'hygiène M35 = "Anticiper la fin de la maintenance des
		// logiciels et systèmes". L'ancien M30 pointait en réalité (selon le
		// PDF officiel 2017) sur "Sécurisation physique des terminaux nomades"
		// — sujet sans rapport. Mapping corrigé en v3.1.16.
		{Framework: FrameworkANSSIGuideHyg, Control: "M35"},
	},

	// ────────────────────────────────────────────────────────────────────
	// CIS / NIST / DISA native detectors with cross-tags
	// ────────────────────────────────────────────────────────────────────
	"CIS_PASSWORD_POLICY": {
		// PA-099 R40 removed v3.1.16: R40 is Tier 0-specific FGPP, not a
		// generic CIS password policy check.
		{Framework: FrameworkCIS, Control: "§1.1"},
		{Framework: FrameworkHDS, Control: "5.5"},
		{Framework: FrameworkRGPD, Control: "art.32(1)(a)"},
	},
	"CIS_NETWORK_SECURITY": {
		// PA-099 R52 removed v3.1.16: R52 is Tier 0-specific protocol
		// hardening, not generic CIS network security.
		{Framework: FrameworkCIS, Control: "§2.3"},
		{Framework: FrameworkHDS, Control: "5.2"},
		{Framework: FrameworkNIS2, Control: "Art.21(2)(e)"},
	},
	"CIS_USER_RIGHTS": {
		// PA-099 R23 removed v3.1.16: R23 is permissions on Tier 0 accounts
		// and groups in the directory, not generic CIS user-rights GPO.
		{Framework: FrameworkCIS, Control: "§2.2"},
	},
	"NIST_AC_2_ACCOUNT_MANAGEMENT": {
		// PA-099 R29 removed v3.1.16: R29 is reusable secret dissemination,
		// not lifecycle/account management. NIST AC-2 is the precise control.
		{Framework: FrameworkNIST, Control: "AC-2"},
		{Framework: FrameworkHDS, Control: "5.3"},
		{Framework: FrameworkRGPD, Control: "art.32(1)(b)"},
	},
	"NIST_AC_6_LEAST_PRIVILEGE": {
		{Framework: FrameworkNIST, Control: "AC-6"},
		{Framework: FrameworkANSSIPA099, Control: "R1"},
		{Framework: FrameworkANSSIPA099, Control: "R8"},
		{Framework: FrameworkHDS, Control: "5.6"},
	},
	"NIST_IA_5_AUTHENTICATOR": {
		// PA-099 R40 removed v3.1.16: R40 is Tier 0-specific FGPP.
		// PA-099 R66 removed v3.1.16: R66 is Kerberos pre-auth Tier 0,
		// not MFA/strong-authenticator handling.
		{Framework: FrameworkNIST, Control: "IA-5"},
		{Framework: FrameworkHDS, Control: "5.1.4"},
		{Framework: FrameworkCIS, Control: "§1.1"},
	},
	"NIST_AU_2_AUDIT_EVENTS": {
		{Framework: FrameworkNIST, Control: "AU-2"},
		{Framework: FrameworkANSSIPA099, Control: "R13"},
		{Framework: FrameworkHDS, Control: "5.4"},
	},
	"DISA_ACCOUNT_POLICIES": {
		// PA-099 R40 removed v3.1.16: R40 is Tier 0 FGPP, not generic
		// DISA account policy GPO.
		{Framework: FrameworkDISA, Control: "V-73305"},
		{Framework: FrameworkCIS, Control: "§1.1"},
	},
	"DISA_AUDIT_POLICIES": {
		{Framework: FrameworkDISA, Control: "V-73411"},
		{Framework: FrameworkANSSIPA099, Control: "R13"},
		{Framework: FrameworkNIST, Control: "AU-2"},
	},

	// v3.1.17 — GPO password in SYSVOL covers the GPP cpassword vulnerability
	// (MS14-025). Direct mapping to PA-099 R32 ("Forbid passwords stored in
	// Group Policy Preferences") and to Guide d'hygiène M11 (protect stored pwds).
	"GPO_PASSWORD_IN_SYSVOL": {
		{Framework: FrameworkANSSIPA099, Control: "R32", Severity: "critical"},
		{Framework: FrameworkANSSIGuideHyg, Control: "M11"},
		{Framework: FrameworkRGPD, Control: "art.32(1)(a)"},
		{Framework: FrameworkNIS2, Control: "Art.21(2)(h)"},
	},

	// ────────────────────────────────────────────────────────────────────
	// v3.1.17 — Phase B detectors (LDAP-only Tier 0 baseline)
	// ────────────────────────────────────────────────────────────────────
	"ANSSI_R15_LOW_FUNCTIONAL_LEVEL": {
		{Framework: FrameworkANSSIPA099, Control: "R15"},
		{Framework: FrameworkANSSIGuideHyg, Control: "M35"}, // EOL anticipation = legacy FL
	},
	"ANSSI_R19_SERVER_CORE_NOT_USED": {
		{Framework: FrameworkANSSIPA099, Control: "R19+"},
	},
	"ANSSI_R40_NO_PSO_TIER0": {
		{Framework: FrameworkANSSIPA099, Control: "R40"},
	},
	"ANSSI_R42_TRUST_PASSWORD_OLD": {
		{Framework: FrameworkANSSIPA099, Control: "R42"},
	},
	"ANSSI_R43_DC_PASSWORD_OLD": {
		{Framework: FrameworkANSSIPA099, Control: "R43"},
	},
	// v3.1.21 dedup — ANSSI_R69_TIER0_SPN_EXPOSED removed (KERBEROASTING_RISK absorbed Tier 0 split + mapping added below).
	"M12_DEFAULT_ADMIN_NOT_RENAMED": {
		{Framework: FrameworkANSSIGuideHyg, Control: "M12"},
		// v3.1.21 dedup — absorbed from deleted ANSSI_R2_1_BUILTIN_ADMIN_NOT_RENAMED.
		{Framework: FrameworkANSSIPA099, Control: "R44"},
	},

	// ────────────────────────────────────────────────────────────────────
	// v3.1.17 — Phase C detectors (GPO/SYSVOL VBS+NTLM hardening)
	// ────────────────────────────────────────────────────────────────────
	"BP039_VBS_OFF": {
		{Framework: FrameworkANSSIBP039, Control: "R5"},
	},
	"BP039_HVCI_OFF": {
		{Framework: FrameworkANSSIBP039, Control: "R8"},
	},
	"BP039_HVCI_NO_UEFI_LOCK": {
		{Framework: FrameworkANSSIBP039, Control: "R9"},
	},
	"BP039_CRED_GUARD_LIMITED_SCOPE": {
		{Framework: FrameworkANSSIBP039, Control: "R10*"},
		{Framework: FrameworkANSSIBP039, Control: "R10**"},
	},
	"BP039_CRED_GUARD_NO_UEFI_LOCK": {
		{Framework: FrameworkANSSIBP039, Control: "R14"},
	},
	"BP039_CCI_NOT_DEPLOYED": {
		{Framework: FrameworkANSSIBP039, Control: "R6"},
		{Framework: FrameworkANSSIBP039, Control: "R7"},
		{Framework: FrameworkANSSIBP039, Control: "R7*"},
		{Framework: FrameworkANSSIBP039, Control: "R7**"},
	},
	"BP039_PRIV_ACCOUNTS_CACHED": {
		{Framework: FrameworkANSSIBP039, Control: "R13"},
	},
	"ANSSI_R31_SCRIPT_SECRETS": {
		{Framework: FrameworkANSSIPA099, Control: "R31", Severity: "high"},
	},
	"ANSSI_R37_WEAK_CERT_TEMPLATES": {
		{Framework: FrameworkANSSIPA099, Control: "R37", Severity: "high"},
	},
	"ANSSI_R73_NTLM_OUTBOUND_TIER0": {
		{Framework: FrameworkANSSIPA099, Control: "R73"},
	},
	"ANSSI_R74_NTLM_OUTBOUND_DOMAIN": {
		{Framework: FrameworkANSSIPA099, Control: "R74+"},
	},
	"M29_LOCAL_ADMIN_NOT_RESTRICTED": {
		{Framework: FrameworkANSSIGuideHyg, Control: "M29"},
	},

	// ────────────────────────────────────────────────────────────────────
	// v3.1.18 — Phase D detectors (zero-bullshit ANSSI push)
	// ────────────────────────────────────────────────────────────────────
	"ANSSI_R36_CA_RISKS": {
		{Framework: FrameworkANSSIPA099, Control: "R36", Severity: "high"},
	},
	"ANSSI_R49_R50_MGMT_CATEGORIZATION": {
		{Framework: FrameworkANSSIPA099, Control: "R49"},
		{Framework: FrameworkANSSIPA099, Control: "R50"},
	},
	"ANSSI_R59_TIER0_OU_POLICIES": {
		{Framework: FrameworkANSSIPA099, Control: "R59", Severity: "critical"},
	},
	"ANSSI_R79_RDP_NOT_HARDENED": {
		{Framework: FrameworkANSSIPA099, Control: "R79"},
	},
	"ANSSI_R82_R83_ADMIN_ARCHITECTURE": {
		{Framework: FrameworkANSSIPA099, Control: "R82"},
		{Framework: FrameworkANSSIPA099, Control: "R83"},
	},
	"ANSSI_R86_ADMIN_FOREST_SEGREGATION": {
		{Framework: FrameworkANSSIPA099, Control: "R86", Severity: "high"},
	},

	// ────────────────────────────────────────────────────────────────────
	// Custom-detector ↔ ANSSI dedup mappings (added when removing 15 ANSSI
	// duplicates that were checking the exact same registry key / group
	// membership as a pre-existing custom detector). Each entry below
	// migrates the framework controls from the deleted ANSSI detector
	// onto the surviving custom detector — preserving compliance score
	// coverage without double-counting findings or risk score.
	//
	// Removed detectors: ANSSI_R34_WDIGEST_ENABLED, ANSSI_R34_LSA_PROTECTION_OFF,
	// ANSSI_R35_CREDENTIAL_GUARD_OFF, ANSSI_R34_1_CACHED_LOGONS_TOO_HIGH,
	// PA038_ZEROLOGON_ENFORCEMENT_OFF, PA038_LLMNR_ENABLED,
	// PA038_HARDENED_UNC_PATHS_MISSING, PA038_BITLOCKER_NOT_REQUIRED,
	// PA038_DEFENDER_ASR_NOT_ENABLED, PA038_FIREWALL_OUTBOUND_NOT_RESTRICTED,
	// ANSSI_R19_DNSADMINS_NOT_EMPTY, ANSSI_R20_1_BACKUP_OPERATORS_MEMBER,
	// ANSSI_R20_2_PRINT_OPERATORS_MEMBER, ANSSI_R3_1_SMARTCARD_NOT_REQUIRED,
	// ANSSI_R11_ADMINS_NOT_IN_PROTECTED_USERS, ANSSI_R17_SCHEMA_ENTERPRISE_ADMINS_NOT_EMPTY,
	// ANSSI_R69_TIER0_SPN_EXPOSED, ANSSI_R2_1_BUILTIN_ADMIN_NOT_RENAMED.
	// ────────────────────────────────────────────────────────────────────
	"WDIGEST_ENABLED": {
		// PA-099 R29 confirmed T_113: R29 (p.46) scopes itself to "toutes
		// formes" of reusable secrets, explicitly listing "mots de passe"
		// alongside NTLM hashes/Kerberos tickets/cert keys — WDigest keeps a
		// reversibly-encrypted (crackable to cleartext) copy of the user's
		// password resident in LSASS memory, i.e. exactly a password
		// "stocké" per R29's rule text. PA-099 has no WDigest-specific
		// R-code (zero hits for "WDigest"/"digest" in the published text);
		// this is the same "englobé" reasoning the document itself applies
		// to Protected Users' cache limitation (Annexe B, p.125) and to
		// cached-logon passwords below.
		{Framework: FrameworkANSSIPA099, Control: "R29"},
	},
	"LSA_PROTECTION_DISABLED": {
		// PA-099 R62 = "Use Credential Guard only as defense in depth" —
		// LSA Protection (RunAsPPL) is the same family of LSASS hardening.
		{Framework: FrameworkANSSIPA099, Control: "R62"},
	},
	"CREDENTIAL_GUARD_DISABLED": {
		{Framework: FrameworkANSSIPA099, Control: "R62"},
		{Framework: FrameworkANSSIBP039, Control: "R10"},
	},
	"CACHED_LOGONS_EXCESSIVE": {
		// PA-099 R29 confirmed T_113: §4.5 "Cas particulier des mots de
		// passe d'ouverture de session en cache" (p.82-83) explicitly folds
		// MS-CACHE v1/v2 offline-logon password hashes into the general R29
		// dissemination risk — "leur risque de dissémination est équivalent"
		// to NTLM hashes/Kerberos secrets — and deliberately withholds R61
		// from it (R61 is scoped to "condensats NTLM et... secrets
		// Kerberos" specifically, not MS-CACHE).
		{Framework: FrameworkANSSIPA099, Control: "R29"},
	},
	"ZEROLOGON_PATCH_ENFORCEMENT": {
		{Framework: FrameworkANSSIPA099, Control: "R18"},
		{Framework: FrameworkANSSIPA099, Control: "R52", Severity: "critical"},
		{Framework: FrameworkNIS2, Control: "Art.21(2)(e)"},
	},
	"GPO_LLMNR_NOT_DISABLED": {
		{Framework: FrameworkNIS2, Control: "Art.21(2)(e)"},
	},
	"HARDENED_UNC_PATHS_WEAK": {
		{Framework: FrameworkANSSIPA099, Control: "R18"},
		{Framework: FrameworkANSSIPA099, Control: "R52"},
		{Framework: FrameworkNIS2, Control: "Art.21(2)(e)"},
	},
	"BITLOCKER_NOT_REQUIRED": {
		// BitLocker has no dedicated R-code in PA-099/BP-039 — keep just the
		// cross-framework links present on the deleted PA038_BITLOCKER mapping.
		{Framework: FrameworkNIS2, Control: "Art.21(2)(h)"},
		{Framework: FrameworkRGPD, Control: "art.32(1)(a)"},
	},
	"DEFENDER_ASR_NOT_CONFIGURED": {
		{Framework: FrameworkANSSIPA099, Control: "R11"},
		{Framework: FrameworkANSSIPA099, Control: "R18"},
		{Framework: FrameworkNIS2, Control: "Art.21(2)(e)"},
	},
	"FIREWALL_OUTBOUND_NOT_BLOCKED": {
		// Note: this custom detector reads `FirewallOutboundAction` with
		// the CORRECT Microsoft semantics (1=block). The deleted PA038
		// counterpart had an inverted check (0=block) that produced false
		// positives in production since v3.1.17 — fix shipped via the
		// deletion of PA038_FIREWALL_OUTBOUND_NOT_RESTRICTED in this PR.
		{Framework: FrameworkNIS2, Control: "Art.21(2)(e)"},
		{Framework: FrameworkANSSIGuideHyg, Control: "M17"},
	},
	"DNS_ADMINS_MEMBER": {
		{Framework: FrameworkANSSIPA099, Control: "R23"},
	},
	"ADMIN_NO_SMARTCARD": {
		// PA-099 v1.0 has no dedicated R-code for smartcard-required enforcement;
		// R66 (p.92) is exclusively Kerberos pre-authentication for Tier 0,
		// already correctly claimed by ASREP_ROASTING_RISK. See T_103/M_028.
		{Framework: FrameworkNIS2, Control: "Art.21(2)(j)"},
	},
	"SCHEMA_ADMINS_NOT_EMPTY": {
		// Custom is extended in this PR to ALSO check Enterprise Admins
		// (was Schema Admins only) — covering the full scope of R17.
		{Framework: FrameworkANSSIPA099, Control: "R23"},
	},
	"KERBEROASTING_RISK": {
		// Custom is refactored in this PR to use helpers.Tier0Members for
		// recursive Tier 0 expansion + AdminCount=1 + tier0_groups.yaml.
		// Emits 2 findings : Tier 0 (Critical) + non-Tier 0 (Medium).
		{Framework: FrameworkANSSIPA099, Control: "R69", Severity: "critical"},
		{Framework: FrameworkANSSIPA099, Control: "R70"},
		{Framework: FrameworkANSSIPA099, Control: "R70-"},
	},
}

// Mappings returns the central detector → []ComplianceMapping table. Used by
// `etc-collector compliance verify` to display per-framework coverage. The
// returned map MUST NOT be mutated by callers.
func Mappings() map[string][]types.ComplianceMapping {
	return mappings
}

// EnrichWithCompliance decorates each finding in-place with its compliance
// mappings (if any). Called from audit.Engine.Run just before serialization.
//
// Findings whose Type is not in the mappings table are left untouched —
// no allocation, no JSON noise.
func EnrichWithCompliance(findings []types.Finding) {
	for i := range findings {
		if mapping, ok := mappings[findings[i].Type]; ok {
			findings[i].Compliance = mapping
		}
	}
}

// MappingsFor returns the framework mappings for a given detector ID,
// or nil if none. Exposed for the `audit list` sub-command and the report
// generator.
func MappingsFor(detectorID string) []types.ComplianceMapping {
	return mappings[detectorID]
}

// AllMappedDetectors returns the list of detector IDs that have at least
// one framework mapping. Order is non-deterministic — callers that need
// stable output should sort.
func AllMappedDetectors() []string {
	out := make([]string, 0, len(mappings))
	for id := range mappings {
		out = append(out, id)
	}
	return out
}

// DetectorsForFramework returns the IDs of detectors mapped to a given
// framework. Used by audit/profiles.go to build the compliance-anssi /
// compliance-hds / compliance-rgpd scope profiles.
func DetectorsForFramework(framework string) []string {
	var out []string
	for id, ms := range mappings {
		for _, m := range ms {
			if m.Framework == framework {
				out = append(out, id)
				break
			}
		}
	}
	return out
}
