package catalogs

// DISA STIG — Active Directory Domain STIG.
//
// Source : https://public.cyber.mil/stigs/downloads/
// Published by Defense Information Systems Agency (DISA) for U.S. DoD use.
//
// The Active Directory Domain STIG enumerates findings (Vulnerability IDs
// V-NNNNN) covering domain configuration, account policies, audit policies,
// and group memberships. Catalog covers the most commonly cited findings
// that map to ETC detectors. Specific V-NNNNN codes change between STIG
// versions; we use stable thematic codes here.

func init() {
	register(&Catalog{
		Framework: "DISA_STIG",
		Source:    "https://public.cyber.mil/stigs/downloads/",
		Version:   "Active Directory Domain STIG V3R3",
		Controls:  disaSTIGControls,
	})
}

var disaSTIGControls = []ControlSpec{
	// V-732NN series — Account Policies
	{Code: "V-73305", Title: "Domain account password policy must enforce 14-character minimum length", Section: "Account Policies", Automatable: true},
	{Code: "V-73307", Title: "Domain account password policy must enforce password complexity", Section: "Account Policies", Automatable: true},
	{Code: "V-73309", Title: "Domain account password policy must enforce password history of 24 passwords", Section: "Account Policies", Automatable: true},
	{Code: "V-73311", Title: "Domain account lockout duration must be 15 minutes or more", Section: "Account Policies", Automatable: true},
	{Code: "V-73313", Title: "Domain account lockout threshold must be 3 attempts or fewer", Section: "Account Policies", Automatable: true},

	// V-734NN series — Audit Policies
	{Code: "V-73411", Title: "Domain controllers must audit Account Logon events (Success and Failure)", Section: "Audit Policies", Automatable: true},
	{Code: "V-73413", Title: "Domain controllers must audit Account Management events (Success and Failure)", Section: "Audit Policies", Automatable: true},
	{Code: "V-73415", Title: "Domain controllers must audit Directory Service Access events (Success and Failure)", Section: "Audit Policies", Automatable: true},
	{Code: "V-73417", Title: "Domain controllers must audit Logon events (Success and Failure)", Section: "Audit Policies", Automatable: true},
	{Code: "V-73419", Title: "Domain controllers must audit Object Access events (Failure at minimum)", Section: "Audit Policies", Automatable: true},
	{Code: "V-73421", Title: "Domain controllers must audit Policy Change events (Success and Failure)", Section: "Audit Policies", Automatable: true},
	{Code: "V-73423", Title: "Domain controllers must audit Privilege Use events (Failure at minimum)", Section: "Audit Policies", Automatable: true},
	{Code: "V-73425", Title: "Domain controllers must audit System events (Success and Failure)", Section: "Audit Policies", Automatable: true},

	// V-7350NN series — Privileged group membership
	{Code: "V-73501", Title: "Membership of Domain Admins group must be tightly controlled and reviewed", Section: "Privileged Groups", Automatable: true},
	{Code: "V-73503", Title: "Membership of Enterprise Admins group must be tightly controlled and reviewed", Section: "Privileged Groups", Automatable: true},
	{Code: "V-73505", Title: "Membership of Schema Admins group must be empty unless schema modification is in progress", Section: "Privileged Groups", Automatable: true},
}
