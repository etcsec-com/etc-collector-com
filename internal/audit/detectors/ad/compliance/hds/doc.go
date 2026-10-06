// Package hds implements detectors specific to the French HDS v1.1 reference
// (Hébergement de Données de Santé). Most HDS technical requirements map to
// generic detectors that already exist in ETC; this package adds the few
// HDS-specific checks that have no clean home elsewhere.
//
// Reference: Référentiel HDS Exigences, V1.1.20221027 ("en concertation"),
// Agence du Numérique en Santé. https://esante.gouv.fr/labels-certifications/hds
//
// Every detector in this package used to cite a specific "5.x" (or "5.x.y")
// requirement number that does not exist in this document. Verified against
// the document's own table of contents and body text: chapter 5 ("Exigences
// relatives au SMSI") is explicitly numbered to mirror ISO 27001 clauses 4-10
// and therefore starts at 5.4 and runs through 5.10 only (5.4 Contexte de
// l'organisation, 5.5 Gouvernance, 5.6 Planification, 5.7 Support, 5.8
// Fonctionnement, 5.9 Evaluation des performances, 5.10 Amélioration) - there
// is no 5.1, 5.2, 5.1.4, or 5.14 anywhere in it. The only "5.14" in the whole
// document is inside Annexe 2 ("Matrice de correspondance avec
// SecNumCloud"), where it names ISO/IEC 27001:2022 Annex A control "5.14 -
// Transferts d'information" (mapped to SecNumCloud §10.2 "Chiffrement des
// flux") - an unrelated cross-reference table entry, not an HDS exigence
// number, and nothing to do with pentest cadence. None of the five topics
// covered in this package (strong authentication, encryption in transit,
// access traceability, business continuity, pentest cadence) has a dedicated
// numbered HDS requirement in this document; the fabricated numbers have
// been removed rather than replaced with different invented ones. The
// detector IDs (HDS_5_1_4_STRONG_AUTH etc.) keep their fabricated-looking
// numbers because they are registered keys used outside this
// package (internal/audit/compliance/mappings.go owns them).
package hds
