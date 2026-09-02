package catalogs

// CIS Controls v8.1 — Center for Internet Security Critical Security Controls.
//
// Source : https://www.cisecurity.org/controls/v8
// Published : May 2024 (v8.1)
//
// CIS Controls v8 organizes 18 top-level Controls with sub-Safeguards.
// Catalog focuses on the AD-relevant Safeguards and the Microsoft Windows
// Server Benchmark sections that ETC can verify.

func init() {
	register(&Catalog{
		Framework: "CIS_v8",
		Source:    "https://www.cisecurity.org/controls/v8",
		Version:   "CIS Controls v8.1 (2024-05) + CIS Microsoft Windows Server 2022 Benchmark v3.0.0",
		Controls:  cisV8Controls,
	})
}

var cisV8Controls = []ControlSpec{
	// CIS Controls v8 — top-level Controls relevant to AD/Windows
	{Code: "CIS-1", Title: "Inventory and Control of Enterprise Assets", Section: "Asset management", Automatable: false, Rationale: "Asset inventory across entire enterprise, beyond AD"},
	{Code: "CIS-2", Title: "Inventory and Control of Software Assets", Section: "Asset management", Automatable: false, Rationale: "Software inventory, requires endpoint scanning"},
	{Code: "CIS-3", Title: "Data Protection", Section: "Data protection", Automatable: false, Rationale: "Data classification and encryption, application-level"},
	{Code: "CIS-4", Title: "Secure Configuration of Enterprise Assets and Software", Section: "Configuration", Automatable: true},
	{Code: "CIS-5", Title: "Account Management", Section: "Identity", Automatable: true},
	{Code: "CIS-6", Title: "Access Control Management", Section: "Identity", Automatable: true},
	{Code: "CIS-7", Title: "Continuous Vulnerability Management", Section: "Vulnerability management", Automatable: false, Rationale: "Vulnerability scanning process, outside AD"},
	{Code: "CIS-8", Title: "Audit Log Management", Section: "Logging", Automatable: true},
	{Code: "CIS-9", Title: "Email and Web Browser Protections", Section: "Email/Web", Automatable: false, Rationale: "Mail/Web gateway controls, outside AD"},
	{Code: "CIS-10", Title: "Malware Defenses", Section: "Endpoint protection", Automatable: false, Rationale: "AV/EDR deployment, outside AD"},
	{Code: "CIS-11", Title: "Data Recovery", Section: "Backup", Automatable: true},
	{Code: "CIS-12", Title: "Network Infrastructure Management", Section: "Network", Automatable: false, Rationale: "Network device configuration, outside AD"},
	{Code: "CIS-13", Title: "Network Monitoring and Defense", Section: "Network", Automatable: false, Rationale: "Network IDS/IPS, outside AD"},
	{Code: "CIS-14", Title: "Security Awareness and Skills Training", Section: "Training", Automatable: false, Rationale: "Training program, organizational"},
	{Code: "CIS-15", Title: "Service Provider Management", Section: "Third party", Automatable: false, Rationale: "Vendor management, organizational"},
	{Code: "CIS-16", Title: "Application Software Security", Section: "AppSec", Automatable: false, Rationale: "Application security testing, outside AD"},
	{Code: "CIS-17", Title: "Incident Response Management", Section: "Incident response", Automatable: false, Rationale: "Incident response process, organizational"},
	{Code: "CIS-18", Title: "Penetration Testing", Section: "Testing", Automatable: false, Rationale: "Pentest cadence, organizational"},

	// CIS Microsoft Windows Server 2022 Benchmark — relevant sections (kept legacy keys for backward compatibility with mappings.go)
	{Code: "§1.1", Title: "Account Policies — Password Policy", Section: "Windows Server Benchmark §1.1", Automatable: true},
	{Code: "§2.2", Title: "Local Policies — User Rights Assignment", Section: "Windows Server Benchmark §2.2", Automatable: true},
	{Code: "§2.3", Title: "Local Policies — Security Options (Network/Microsoft network client)", Section: "Windows Server Benchmark §2.3", Automatable: true},
	{Code: "§17", Title: "Advanced Audit Policy Configuration", Section: "Windows Server Benchmark §17", Automatable: true},
}
