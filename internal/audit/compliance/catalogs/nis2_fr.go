package catalogs

// NIS2 — Directive (UE) 2022/2555, Article 21(2) — Mesures de gestion
// des risques en matière de cybersécurité.
//
// Source : https://eur-lex.europa.eu/eli/dir/2022/2555/oj
// Transposition FR : loi n° 2024-449 du 21 mai 2024.
//
// Article 21(2) lists 10 categories of cybersecurity risk management
// measures that essential and important entities must implement.

func init() {
	register(&Catalog{
		Framework: "NIS2_FR",
		Source:    "https://eur-lex.europa.eu/eli/dir/2022/2555/oj",
		Version:   "Directive (EU) 2022/2555, Article 21(2)",
		Controls:  nis2FRControls,
	})
}

var nis2FRControls = []ControlSpec{
	{Code: "Art.21(2)(a)", Title: "Policies on risk analysis and information system security", Section: "Article 21(2)", Automatable: true},
	{Code: "Art.21(2)(b)", Title: "Incident handling", Section: "Article 21(2)", Automatable: true},
	{Code: "Art.21(2)(c)", Title: "Business continuity (backup management, disaster recovery, crisis management)", Section: "Article 21(2)", Automatable: true},
	{Code: "Art.21(2)(d)", Title: "Supply chain security including security-related aspects concerning the relationships between each entity and its direct suppliers or service providers", Section: "Article 21(2)", Automatable: false, Rationale: "Supply chain governance (SBOM/vendor management), organizational"},
	{Code: "Art.21(2)(e)", Title: "Security in network and information systems acquisition, development and maintenance, including vulnerability handling and disclosure", Section: "Article 21(2)", Automatable: true},
	{Code: "Art.21(2)(f)", Title: "Policies and procedures to assess the effectiveness of cybersecurity risk-management measures", Section: "Article 21(2)", Automatable: false, Rationale: "Effectiveness assessment process, organizational"},
	{Code: "Art.21(2)(g)", Title: "Basic cyber hygiene practices and cybersecurity training", Section: "Article 21(2)", Automatable: false, Rationale: "Training program, organizational"},
	{Code: "Art.21(2)(h)", Title: "Policies and procedures regarding the use of cryptography and, where appropriate, encryption", Section: "Article 21(2)", Automatable: true},
	{Code: "Art.21(2)(i)", Title: "Human resources security, access control policies and asset management", Section: "Article 21(2)", Automatable: true},
	{Code: "Art.21(2)(j)", Title: "Use of multi-factor authentication or continuous authentication solutions, secured voice/video/text communications", Section: "Article 21(2)", Automatable: true},
}
