package catalogs

// ANSSI-BP-039 v1.0 — Mise en œuvre des fonctionnalités de sécurité de
// Windows 10 reposant sur la virtualisation.
//
// Source officielle (vérifiée 2026-04-27 contre le PDF) :
//   https://cyber.gouv.fr/sites/default/files/2017/11/np_securisation_windows10_securite_reposant_sur_la_virtualisation_v1.pdf
// Référence ANSSI-BP-039, version 1.0, publié le 08/11/2017.
//
// Le document liste 15 recommandations principales (R1-R15) plus 6 sous-
// recommandations matérialisées par les suffixes `*` (allègement) et `**`
// (renforcement) sur R4, R7 et R10 — total 21 controls.
//
// IMPORTANT — Réécrit en v3.1.16 après fact-check externe contre le PDF
// officiel. La version précédente (v3.0.x à v3.1.15) utilisait des codes
// fabriqués (Secure-Boot, TPM-2.0, VBS, BitLocker, ...) qui n'existent dans
// AUCUNE publication ANSSI. L'auditabilité par un expert ANSSI exigeait que
// chaque code matche byte-for-byte la publication source.

func init() {
	register(&Catalog{
		Framework: "ANSSI_BP039",
		Source:    "https://cyber.gouv.fr/sites/default/files/2017/11/np_securisation_windows10_securite_reposant_sur_la_virtualisation_v1.pdf",
		Version:   "v1.0 (08/11/2017)",
		FetchedAt: "2026-04-27",
		Controls:  anssiBP039Controls,
	})
}

// All controls below were extracted byte-for-byte from the official PDF via
// pdftotext and reviewed against the published "Liste des recommandations"
// section. The English Title is a faithful technical translation of the
// French original (kept in OfficialFR — to be wired in v3.1.16 Phase 4).
//
// Automatable classification:
//   - true  = the recommendation prescribes a setting that ETC can verify by
//     reading the GPO XML in SYSVOL (when the policy is enforced at the
//     domain level) or by checking registry keys reflected in the AD GPO.
//   - false = the recommendation is about hardware procurement, UEFI
//     firmware, physical security or end-user training — out of scope for
//     an LDAP/SYSVOL audit. ETC will never produce a finding for these.
//
// Most Automatable=true controls do NOT currently have a corresponding
// detector — building the missing detectors is the v3.1.17 chantier.
var anssiBP039Controls = []ControlSpec{
	// === Section 2 — Sécurité reposant sur la virtualisation (VBS) ===
	{Code: "R1", Title: "Integrate VSM/VBS compatibility into hardware procurement processes", OfficialFR: "Intégrer la compatibilité VSM/VBS dans le processus d'achat de matériel", Section: "Hardware procurement", Automatable: false, Rationale: "Procurement / vendor process, outside of AD scope"},
	{Code: "R2", Title: "Protect access to UEFI", OfficialFR: "Protéger les accès à l'UEFI", Section: "UEFI protection", Automatable: false, Rationale: "Per-endpoint UEFI configuration, not auditable from AD"},
	{Code: "R3", Title: "Keep UEFI firmware components up to date", OfficialFR: "Maintenir à jour les composants logiciels UEFI", Section: "UEFI maintenance", Automatable: false, Rationale: "Patch management, requires per-endpoint inventory"},
	{Code: "R4", Title: "Enable UEFI Secure Boot", OfficialFR: "Activer le démarrage sécurisé UEFI", Section: "UEFI Secure Boot", Automatable: false, Rationale: "Endpoint firmware setting, not auditable from AD/SYSVOL"},
	{Code: "R4*", Title: "Skip the UEFI key-store conformity check (standard security needs)", OfficialFR: "Ignorer le contrôle de conformité de l'IGC UEFI", Section: "UEFI Secure Boot", Automatable: false, Rationale: "Process choice on Secure Boot key-store auditing, organizational"},
	{Code: "R4**", Title: "Implement the UEFI key-store conformity check (high security needs)", OfficialFR: "Mettre en œuvre du contrôle de conformité de l'IGC UEFI", Section: "UEFI Secure Boot", Automatable: false, Rationale: "Endpoint UEFI key store inspection, requires per-endpoint procedure"},

	// === Section 2.5 — VBS activation ===
	{Code: "R5", Title: "Enable VBS on every compatible workstation", OfficialFR: "Activer la VBS sur tout poste de travail compatible", Section: "VBS activation", Automatable: true, Rationale: "Verifiable via Group Policy (Device Guard) deployed through SYSVOL"},

	// === Section 3 — Device Guard / CCI / HVCI ===
	{Code: "R6", Title: "Apply Configurable Code Integrity in enforced mode on sensitive workstations", OfficialFR: "Appliquer CCI en mode enforced sur les postes de travail sensibles", Section: "Configurable Code Integrity", Automatable: true, Rationale: "Verifiable via GPO Device Guard CCI policy"},
	{Code: "R7", Title: "Apply Configurable Code Integrity on the other workstations", OfficialFR: "Appliquer CCI sur les autres postes de travail", Section: "Configurable Code Integrity", Automatable: true, Rationale: "Verifiable via GPO Device Guard CCI policy"},
	{Code: "R7*", Title: "Apply CCI in audit mode on the other workstations", OfficialFR: "Appliquer CCI en mode audit sur les autres postes de travail", Section: "Configurable Code Integrity", Automatable: true, Rationale: "Verifiable via GPO Device Guard CCI policy mode flag"},
	{Code: "R7**", Title: "Apply CCI in enforced mode on the other workstations", OfficialFR: "Appliquer CCI en mode enforced sur les autres postes de travail", Section: "Configurable Code Integrity", Automatable: true, Rationale: "Verifiable via GPO Device Guard CCI policy mode flag"},
	{Code: "R8", Title: "Implement HVCI on compatible workstations", OfficialFR: "Mettre en œuvre HVCI sur les postes de travail compatibles", Section: "HVCI", Automatable: true, Rationale: "Verifiable via GPO Device Guard HypervisorEnforcedCodeIntegrity setting"},
	{Code: "R9", Title: "Implement HVCI with UEFI lock", OfficialFR: "Mettre en œuvre HVCI avec verrouillage UEFI", Section: "HVCI", Automatable: true, Rationale: "Verifiable via GPO Device Guard HVCI lock setting"},

	// === Section 4 — Credential Guard ===
	{Code: "R10", Title: "Implement Credential Guard", OfficialFR: "Mettre en œuvre Credential Guard", Section: "Credential Guard", Automatable: true, Rationale: "Verifiable via GPO LsaCfgFlags / Device Guard policy"},
	{Code: "R10*", Title: "Implement Credential Guard on sensitive workstations", OfficialFR: "Mettre en œuvre Credential Guard sur les postes de travail sensibles", Section: "Credential Guard", Automatable: true, Rationale: "Verifiable via GPO scoping (Tier 0/Tier 1 OUs)"},
	{Code: "R10**", Title: "Implement Credential Guard on all workstations", OfficialFR: "Mettre en œuvre Credential Guard sur tous les postes de travail", Section: "Credential Guard", Automatable: true, Rationale: "Verifiable via GPO LsaCfgFlags scope=domain-wide"},
	{Code: "R11", Title: "Ensure physical security of workstations", OfficialFR: "Assurer la sécurité physique des postes de travail", Section: "Physical security", Automatable: false, Rationale: "Physical security control, not auditable from AD"},
	{Code: "R12", Title: "Implement a local administrator password management solution (e.g. LAPS)", OfficialFR: "Mettre en œuvre une solution de gestion des mots de passe administrateurs locaux", Section: "Local admin secrets", Automatable: true, Rationale: "Verifiable via LDAP attribute ms-Mcs-AdmPwdExpirationTime + GPO LAPS deployment"},
	{Code: "R13", Title: "Do not cache AD privileged accounts on workstations", OfficialFR: "Ne pas mémoriser les comptes à privilèges de l'AD", Section: "Privileged account hygiene", Automatable: true, Rationale: "Verifiable via GPO 'Interactive logon: Number of previous logons to cache'"},
	{Code: "R14", Title: "Implement Credential Guard with UEFI lock", OfficialFR: "Mettre en œuvre Credential Guard avec verrouillage UEFI", Section: "Credential Guard", Automatable: true, Rationale: "Verifiable via GPO LsaCfgFlags=2 (Enable with UEFI lock)"},
	{Code: "R15", Title: "Raise user awareness of the Credential Guard UEFI lock", OfficialFR: "Sensibiliser les utilisateurs au verrouillage UEFI de Credential Guard", Section: "User awareness", Automatable: false, Rationale: "User training program, organizational"},
}
