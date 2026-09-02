package catalogs

// RGPD — Règlement Général sur la Protection des Données (UE 2016/679),
// Article 32 — Sécurité du traitement.
//
// Source : https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX%3A32016R0679
// Article 32 enumerates the technical and organisational security measures
// the controller and processor must implement.
//
// Catalog covers article 32 sub-points that map to AD-auditable controls.

func init() {
	register(&Catalog{
		Framework: "RGPD",
		Source:    "https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX%3A32016R0679",
		Version:   "Regulation (EU) 2016/679, Article 32",
		Controls:  rgpdControls,
	})
}

var rgpdControls = []ControlSpec{
	{Code: "art.32(1)(a)", Title: "Pseudonymisation and encryption of personal data", Section: "Article 32(1)", Automatable: true},
	{Code: "art.32(1)(b)", Title: "Ensure ongoing confidentiality, integrity, availability and resilience of processing systems and services", Section: "Article 32(1)", Automatable: true},
	{Code: "art.32(1)(c)", Title: "Ability to restore availability and access to personal data in a timely manner in the event of a physical or technical incident", Section: "Article 32(1)", Automatable: true},
	{Code: "art.32(1)(d)", Title: "Process for regularly testing, assessing and evaluating the effectiveness of technical and organisational measures", Section: "Article 32(1)", Automatable: true},
	{Code: "art.32(2)", Title: "Take account of the risks presented by processing (accidental or unlawful destruction, loss, alteration, unauthorised disclosure of, or access to personal data)", Section: "Article 32(2)", Automatable: false, Rationale: "Risk assessment process, organizational"},
	{Code: "art.32(3)", Title: "Adherence to an approved code of conduct or certification mechanism", Section: "Article 32(3)", Automatable: false, Rationale: "Adherence/certification status, organizational"},
	{Code: "art.32(4)", Title: "Ensure that any natural person acting under the authority of the controller or processor processes personal data only on instructions", Section: "Article 32(4)", Automatable: false, Rationale: "Process and instructions framework, organizational"},
}
