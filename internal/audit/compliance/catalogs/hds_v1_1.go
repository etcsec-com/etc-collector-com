package catalogs

// HDS v1.1 — Référentiel HDS (Hébergement Données de Santé) v1.1.
//
// Source : https://esante.gouv.fr/labels-certifications/hds
// Published by Agence du Numérique en Santé (formerly ASIP Santé).
//
// HDS v1.1 contains 14 chapters of security requirements. ETC catalogs
// the chapters that map to AD-auditable controls (sections 5.1.4 strong
// auth, 5.2 transport encryption, 5.3 access control, 5.4 logging,
// 5.5 password policy, 5.6 privileged accounts, 5.7 backup, 5.8 BCP,
// 5.9 segregation, 5.10 anonymization, 5.11–5.13 outside AD scope,
// 5.14 pentest cadence).

func init() {
	register(&Catalog{
		Framework: "HDS_v1_1",
		Source:    "https://esante.gouv.fr/labels-certifications/hds",
		Version:   "v1.1 (2018)",
		Controls:  hdsV11Controls,
	})
}

var hdsV11Controls = []ControlSpec{
	{Code: "5.1.4", Title: "Strong authentication for access to health data", Section: "Authentication", Automatable: true},
	{Code: "5.2", Title: "Encryption in transit for health data communications", Section: "Transport security", Automatable: true},
	{Code: "5.3", Title: "Access control with least privilege principle", Section: "Access control", Automatable: true},
	{Code: "5.4", Title: "Logging of access to hosted health data", Section: "Audit and traceability", Automatable: true},
	{Code: "5.5", Title: "Strong password policy", Section: "Password policy", Automatable: true},
	{Code: "5.6", Title: "Management of privileged accounts", Section: "Privileged access", Automatable: true},
	{Code: "5.7", Title: "Backup and integrity of health data", Section: "Backup", Automatable: true},
	{Code: "5.8", Title: "Disaster recovery plan (DRP/BCP)", Section: "Business continuity", Automatable: true},
	{Code: "5.9", Title: "Segregation of environments (production / test / development)", Section: "Environment segregation", Automatable: true},
	{Code: "5.10", Title: "Anonymization or pseudonymization of health data", Section: "Data protection", Automatable: false, Rationale: "Application-level data classification, not auditable from AD"},
	{Code: "5.11", Title: "Vulnerability management", Section: "Vulnerability management", Automatable: false, Rationale: "Patch management process, outside AD scope"},
	{Code: "5.12", Title: "Incident response procedures", Section: "Incident response", Automatable: false, Rationale: "Process-based, organizational"},
	{Code: "5.13", Title: "Sub-contractor security framework", Section: "Sub-contracting", Automatable: false, Rationale: "Contractual review, organizational"},
	{Code: "5.14", Title: "Periodic penetration testing cadence", Section: "Security testing", Automatable: false, Rationale: "Process cadence, requires pentest evidence outside AD"},
}
