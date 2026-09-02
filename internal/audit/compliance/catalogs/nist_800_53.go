package catalogs

// NIST SP 800-53 Rev.5 — Security and Privacy Controls for Information
// Systems and Organizations.
//
// Source : https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final
// Published : September 2020 (Rev.5), Patch update December 2023.
//
// NIST SP 800-53 Rev.5 contains ~1000+ controls across 20 families.
// Catalog covers AD-relevant controls in the AC (Access Control),
// AU (Audit and Accountability), IA (Identification and Authentication),
// IR (Incident Response), SC (System and Communications Protection),
// and SI (System and Information Integrity) families.

func init() {
	register(&Catalog{
		Framework: "NIST_800_53",
		Source:    "https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final",
		Version:   "NIST SP 800-53 Rev.5 (2020-09, patch 2023-12)",
		Controls:  nist80053Controls,
	})
}

var nist80053Controls = []ControlSpec{
	// AC — Access Control
	{Code: "AC-2", Title: "Account Management", Section: "Access Control", Automatable: true},
	{Code: "AC-3", Title: "Access Enforcement", Section: "Access Control", Automatable: true},
	{Code: "AC-5", Title: "Separation of Duties", Section: "Access Control", Automatable: true},
	{Code: "AC-6", Title: "Least Privilege", Section: "Access Control", Automatable: true},
	{Code: "AC-7", Title: "Unsuccessful Logon Attempts", Section: "Access Control", Automatable: true},
	{Code: "AC-12", Title: "Session Termination", Section: "Access Control", Automatable: true},
	{Code: "AC-17", Title: "Remote Access", Section: "Access Control", Automatable: true},

	// AU — Audit and Accountability
	{Code: "AU-2", Title: "Event Logging", Section: "Audit and Accountability", Automatable: true},
	{Code: "AU-3", Title: "Content of Audit Records", Section: "Audit and Accountability", Automatable: true},
	{Code: "AU-4", Title: "Audit Log Storage Capacity", Section: "Audit and Accountability", Automatable: true},
	{Code: "AU-9", Title: "Protection of Audit Information", Section: "Audit and Accountability", Automatable: true},
	{Code: "AU-12", Title: "Audit Record Generation", Section: "Audit and Accountability", Automatable: true},

	// IA — Identification and Authentication
	{Code: "IA-2", Title: "Identification and Authentication (Organizational Users)", Section: "Identification and Authentication", Automatable: true},
	{Code: "IA-5", Title: "Authenticator Management", Section: "Identification and Authentication", Automatable: true},
	{Code: "IA-7", Title: "Cryptographic Module Authentication", Section: "Identification and Authentication", Automatable: true},
	{Code: "IA-8", Title: "Identification and Authentication (Non-Organizational Users)", Section: "Identification and Authentication", Automatable: true},

	// IR — Incident Response
	{Code: "IR-4", Title: "Incident Handling", Section: "Incident Response", Automatable: false, Rationale: "Incident response process, organizational"},
	{Code: "IR-5", Title: "Incident Monitoring", Section: "Incident Response", Automatable: true},
	{Code: "IR-6", Title: "Incident Reporting", Section: "Incident Response", Automatable: false, Rationale: "Reporting process, organizational"},

	// SC — System and Communications Protection
	{Code: "SC-7", Title: "Boundary Protection", Section: "System and Communications Protection", Automatable: false, Rationale: "Network firewall posture, outside AD"},
	{Code: "SC-8", Title: "Transmission Confidentiality and Integrity", Section: "System and Communications Protection", Automatable: true},
	{Code: "SC-13", Title: "Cryptographic Protection", Section: "System and Communications Protection", Automatable: true},
	{Code: "SC-23", Title: "Session Authenticity", Section: "System and Communications Protection", Automatable: true},

	// SI — System and Information Integrity
	{Code: "SI-2", Title: "Flaw Remediation", Section: "System and Information Integrity", Automatable: false, Rationale: "Patch management process, outside AD"},
	{Code: "SI-4", Title: "System Monitoring", Section: "System and Information Integrity", Automatable: true},
}
