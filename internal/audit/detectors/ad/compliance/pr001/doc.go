// Package pr001 implements two AD-observable administration hygiene checks.
//
// the package (and both detectors) previously cited a guide
// "ANSSI PR-001" with numbered sections ("§3.3", "§5.1"). No such ANSSI
// guide exists. The real sources, verified against the published PDFs:
// - dedicated admin accounts: ANSSI-PA-022 v3.0 (11/05/2021) R27
// "Utiliser des comptes d'administration dédiés", p.33 - a DIFFERENT,
// older, non-AD-specific guide from the PA-099 AD guide used elsewhere
// in this package.
// - DC OS obsolescence: ANSSI-PA-099 v1.0 (02/10/2023) R16 "Procéder aux
// montées de versions Windows des systèmes du Tier 0", p.34 (previously
// cited as p.35 - R16's own recommendation text is on p.34; the "Attention"
// advisory box that follows it spills onto p.35, but R16 itself is not).
//
// The package name "pr001" is legacy from the fabricated citation; kept
// as-is because it's also the detector IDs' registered key in
// internal/audit/compliance/mappings.go (out of scope here -
// renaming needs to happen there too).
package pr001
