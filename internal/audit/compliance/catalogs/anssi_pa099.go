package catalogs

// ANSSI-PA-099 v1.0 — Recommandations pour l'administration sécurisée des
// systèmes d'information reposant sur Microsoft Active Directory.
//
// Source officielle (vérifiée 2026-04-27 contre le PDF, Liste des
// recommandations p. 150-152) :
//   https://messervices.cyber.gouv.fr/documents-guides/anssi-guide-admin_securisee_si_ad_v1-0%20(3).pdf
// Page hub : https://cyber.gouv.fr/publications/recommandations-de-securite-relatives-active-directory
// Référence ANSSI-PA-099, version 1.0, publié le 02/10/2023.
//
// Total : 89 main recommendations (R1 to R89) + 6 sub-recommendations
// using "+" suffix (Renforcement = stronger variant) and "-" suffix
// (Réduction = mitigation when main reco can't be applied) :
// R14+, R19+, R25+, R30-, R67-, R70-, R74+, R80-, R80+, R89- = 10 sub-recos
// minus 4 missing-as-bare (R14, R19, R25, R74 only exist as `+`) = 95 controls.
//
// English titles below are technical translations of the official French
// titles (preserved byte-for-byte in the OfficialFR field for ANSSI auditor
// traceability).

func init() {
	register(&Catalog{
		Framework: "ANSSI_PA099",
		Source:    "https://messervices.cyber.gouv.fr/documents-guides/anssi-guide-admin_securisee_si_ad_v1-0%20(3).pdf",
		Version:   "v1.0 (02/10/2023)",
		FetchedAt: "2026-04-27",
		Controls:  anssiPA099Controls,
	})
}

var anssiPA099Controls = []ControlSpec{
	// === Section 2 — Privileged access management model ===
	{Code: "R1", Title: "Implement a privileged access management model", OfficialFR: "Mettre en œuvre un modèle de gestion des accès privilégiés", Section: "Privileged access management model", Automatable: true},
	{Code: "R2", Title: "Protect each tier of the model proportionately", OfficialFR: "Protéger chaque niveau du modèle de manière proportionnée", Section: "Privileged access management model", Automatable: true},
	{Code: "R3", Title: "Define the scope of the model", OfficialFR: "Définir le périmètre d'application du modèle", Section: "Privileged access management model", Automatable: false, Rationale: "Organizational scoping decision, not auditable from AD"},
	{Code: "R4", Title: "Implement an iterative continuous improvement process for IS segregation", OfficialFR: "Mettre en œuvre un processus itératif d'amélioration continue du cloisonnement du SI", Section: "Privileged access management model", Automatable: false, Rationale: "Process-based, not auditable from AD"},

	// === Section 3 — Tier 0 segregation ===
	{Code: "R5", Title: "Identify Tier 1 business assets", OfficialFR: "Identifier les valeurs métiers du Tier 1", Section: "Tier 0 segregation", Automatable: false, Rationale: "Asset inventory exercise, organizational"},
	{Code: "R6", Title: "Analyze attack paths to Tier 0 and Tier 1", OfficialFR: "Analyser les chemins d'attaque vers le Tier 0 et le Tier 1", Section: "Tier 0 segregation", Automatable: true},
	{Code: "R7", Title: "Categorize IS resources into Tiers", OfficialFR: "Catégoriser les ressources du SI en Tiers", Section: "Tier 0 segregation", Automatable: false, Rationale: "Categorization exercise, organizational"},
	{Code: "R8", Title: "Segregate the administration of each Tier", OfficialFR: "Cloisonner l'administration de chaque Tier", Section: "Tier 0 segregation", Automatable: true},
	{Code: "R9", Title: "Identify and conduct architecture work needed for IS segregation", OfficialFR: "Identifier et mener les travaux d'architecture du SI nécessaires à son cloisonnement", Section: "Tier 0 segregation", Automatable: false, Rationale: "Architecture work, organizational"},
	{Code: "R10", Title: "Minimize the exposure of each Tier", OfficialFR: "Minimiser l'exposition de chaque Tiers", Section: "Tier 0 segregation", Automatable: true},
	{Code: "R11", Title: "Apply system and software hardening", OfficialFR: "Appliquer les durcissements systèmes et logiciels", Section: "Tier 0 segregation", Automatable: true},
	{Code: "R12", Title: "Grant rights and privileges through fine-grained delegation", OfficialFR: "Octroyer les droits et privilèges par délégation fine", Section: "Tier 0 segregation", Automatable: true},
	{Code: "R13", Title: "Log and centralize security events", OfficialFR: "Journaliser et centraliser les évènements de sécurité", Section: "Tier 0 segregation", Automatable: true},
	{Code: "R14+", Title: "Automatically detect potential security incidents", OfficialFR: "Détecter automatiquement les potentiels incidents de sécurité", Section: "Tier 0 segregation", Automatable: false, Rationale: "Requires SIEM integration, beyond AD scope"},

	// === Section 3.1 — Hardening Tier 0 systems ===
	{Code: "R15", Title: "Raise functional levels of AD domains and forests", OfficialFR: "Augmenter les niveaux fonctionnels des domaines et des forêts AD", Section: "Tier 0 system hardening", Automatable: true},
	{Code: "R16", Title: "Perform Windows version upgrades on Tier 0 systems", OfficialFR: "Procéder aux montées de versions Windows des systèmes du Tier 0", Section: "Tier 0 system hardening", Automatable: true},
	{Code: "R17", Title: "Maintain reactive lifecycle management on Tier 0 systems", OfficialFR: "Assurer un MCS réactif des systèmes du Tier 0", Section: "Tier 0 system hardening", Automatable: false, Rationale: "v3.1.19 — patch lifecycle cadence requires WSUS sync state + per-host patch level reporting, outside AD/SYSVOL scope"},
	{Code: "R18", Title: "Apply security baselines to Tier 0 systems", OfficialFR: "Appliquer les security baselines aux systèmes du Tier 0", Section: "Tier 0 system hardening", Automatable: true},
	{Code: "R19+", Title: "Use Windows Server Core on the Tier 0 perimeter", OfficialFR: "Utiliser Windows en « Server Core » sur le périmètre du Tier 0", Section: "Tier 0 system hardening", Automatable: true},

	// === Section 3.2 — AD control paths ===
	{Code: "R20", Title: "Analyze control paths to Tier 0 system or configuration containers", OfficialFR: "Analyser les chemins de contrôle vers les conteneurs système ou de configuration du Tier 0", Section: "AD control paths", Automatable: true},
	{Code: "R21", Title: "Preserve permissions on Tier 0 system or configuration containers", OfficialFR: "Préserver les permissions des conteneurs système ou de configuration du Tier 0", Section: "AD control paths", Automatable: true},
	{Code: "R22", Title: "Analyze control paths to Tier 0 accounts and security groups", OfficialFR: "Analyser les chemins de contrôle vers les comptes et groupes de sécurité du Tier 0", Section: "AD control paths", Automatable: true},
	{Code: "R23", Title: "Control permissions applied to Tier 0 accounts and groups in the directory", OfficialFR: "Contrôler les permissions appliquées aux comptes et groupes de Tier 0 dans l'annuaire", Section: "AD control paths", Automatable: true},
	{Code: "R24", Title: "Harden configuration of outgoing extra-forest AD trust relationships", OfficialFR: "Durcir la configuration des relations d'approbation AD sortantes extraforêt", Section: "AD control paths", Automatable: true},
	{Code: "R25+", Title: "Use outgoing trusts with selective authentication", OfficialFR: "Utiliser des relations d'approbation sortantes avec authentification sélective", Section: "AD control paths", Automatable: true},
	{Code: "R26", Title: "Forbid Kerberos delegation across incoming trusts", OfficialFR: "Interdire la délégation Kerberos à travers les relations d'approbation entrantes", Section: "AD control paths", Automatable: true},
	{Code: "R27", Title: "Regularly use AD control path analysis tools", OfficialFR: "Utiliser régulièrement des outils d'analyse des chemins de contrôle AD", Section: "AD control paths", Automatable: false, Rationale: "Recommends external tooling cadence, organizational"},
	{Code: "R28", Title: "Regularly use the ANSSI ADS service (where applicable)", OfficialFR: "Utiliser régulièrement le service ADS de l'ANSSI (si applicable)", Section: "AD control paths", Automatable: false, Rationale: "External ANSSI service usage, organizational"},

	// === Section 3.3 — Reusable authentication secrets ===
	{Code: "R29", Title: "Control the dissemination of reusable authentication secrets", OfficialFR: "Maîtriser la dissémination de toute forme de secret d'authentification réutilisable", Section: "Reusable authentication secrets", Automatable: true},
	{Code: "R30", Title: "Diversify and automatically rotate local admin account passwords", OfficialFR: "Diversifier et renouveler automatiquement les mots de passe des comptes admin locaux", Section: "Reusable authentication secrets", Automatable: true},
	{Code: "R30-", Title: "Manually diversify local admin accounts", OfficialFR: "Diversifier manuellement les comptes admin locaux", Section: "Reusable authentication secrets", Automatable: true},
	{Code: "R31", Title: "Address risks tied to reusable secrets in scripts", OfficialFR: "Traiter les risques liés aux secrets réutilisables figurant dans des scripts", Section: "Reusable authentication secrets", Automatable: true},
	{Code: "R32", Title: "Forbid passwords stored in Group Policy Preferences", OfficialFR: "Prohiber les mots de passe enregistrés dans des GPP", Section: "Reusable authentication secrets", Automatable: true},
	{Code: "R33", Title: "Address risks tied to reusable secrets of scheduled tasks and Windows services", OfficialFR: "Traiter les risques liés aux secrets réutilisables des tâches planifiées et des services Windows", Section: "Reusable authentication secrets", Automatable: true},
	{Code: "R34", Title: "Address risks tied to content executed by scheduled tasks and Windows services", OfficialFR: "Traiter les risques liés au contenu exécuté par les tâches planifiées et services Windows", Section: "Reusable authentication secrets", Automatable: false, Rationale: "v3.1.18 — requires static script analysis (PowerShell AST) beyond LDAP/SYSVOL grep; partial coverage via R31 (cleartext secrets in scripts)"},
	{Code: "R35", Title: "Protect access to network shares hosting executable content", OfficialFR: "Protéger les accès aux partages réseau hébergeant du contenu exécutable", Section: "Reusable authentication secrets", Automatable: false, Rationale: "v3.1.18 — requires SYSVOL Drive Maps (Drives.xml) parser + remote share ACL enumeration not yet implemented; planned v3.1.19"},
	{Code: "R36", Title: "Address risks of certificate authorities affecting Tier 0", OfficialFR: "Traiter les risques inhérents aux IGC qui pèsent sur le Tier 0", Section: "Reusable authentication secrets", Automatable: true},
	{Code: "R37", Title: "Forbid use of weak or vulnerable certificates in Tier 0", OfficialFR: "Proscrire l'utilisation de certificats faibles ou vulnérables du Tier 0", Section: "Reusable authentication secrets", Automatable: true},
	{Code: "R38", Title: "Address risks tied to API access secrets", OfficialFR: "Traiter les risques inhérents aux secrets d'accès à des API sensibles", Section: "Reusable authentication secrets", Automatable: false, Rationale: "v3.1.18 — API access secrets (Azure KeyVault, AWS Secrets Manager, GitHub PATs, gMSA) live outside AD scope and require per-platform connectors"},
	{Code: "R39", Title: "Address risks tied to physical access to Tier 0 reusable secrets", OfficialFR: "Traiter les risques liés aux accès physiques à des secrets réutilisables du Tier 0", Section: "Reusable authentication secrets", Automatable: false, Rationale: "Physical security control, not auditable from AD"},
	{Code: "R40", Title: "Apply fine-grained password policies for Tier 0 accounts", OfficialFR: "Appliquer des stratégies de mot de passe affinées pour les comptes du Tier 0", Section: "Reusable authentication secrets", Automatable: true},
	{Code: "R41", Title: "Regularly renew the krbtgt account password", OfficialFR: "Renouveler régulièrement le mot de passe du compte krbtgt", Section: "Reusable authentication secrets", Automatable: true},
	{Code: "R42", Title: "Control renewal of trust account passwords", OfficialFR: "Contrôler le renouvellement des mots de passe des comptes de trust", Section: "Reusable authentication secrets", Automatable: true},
	{Code: "R43", Title: "Control renewal of sensitive computer account passwords", OfficialFR: "Contrôler le renouvellement des mots de passe des comptes d'ordinateur sensibles", Section: "Reusable authentication secrets", Automatable: true},
	{Code: "R44", Title: "Ensure the strength of the AD built-in administrator password", OfficialFR: "Assurer la robustesse du mot de passe du compte administrateur intégré de l'AD", Section: "Reusable authentication secrets", Automatable: true},

	// === Section 3.4 — Logical storage access ===
	{Code: "R45", Title: "Address backup infrastructure categorization", OfficialFR: "Traiter la problématique de catégorisation des infrastructures de sauvegarde", Section: "Logical storage access", Automatable: false, Rationale: "Architecture categorization decision, organizational"},
	{Code: "R46", Title: "Address network storage infrastructure categorization", OfficialFR: "Traiter la problématique de catégorisation des infrastructures de stockage en réseau", Section: "Logical storage access", Automatable: false, Rationale: "Architecture categorization decision, organizational"},

	// === Section 3.5 — Virtualization infrastructure ===
	{Code: "R47", Title: "Address virtualization infrastructure categorization", OfficialFR: "Traiter la problématique de catégorisation des infrastructures de virtualisation", Section: "Virtualization infrastructure", Automatable: false, Rationale: "Architecture categorization decision, organizational"},

	// === Section 3.6 — Centralized management agents and servers ===
	{Code: "R48", Title: "Limit the presence of centralized management agents on Tier 0 resources", OfficialFR: "Limiter la présence d'agents de gestion centralisée sur les ressources du Tier 0", Section: "Centralized management agents", Automatable: false, Rationale: "v3.1.18 — definition of 'centralized management agent' is environment-specific (no fixed registry/process marker); partial coverage via R49 (categorization heuristic)"},
	{Code: "R49", Title: "Address centralized management agents and servers categorization", OfficialFR: "Traiter la problématique de catégorisation des agents et serveurs de gestion centralisée", Section: "Centralized management agents", Automatable: false, Rationale: "Categorization decision, organizational"},
	{Code: "R50", Title: "Address the special case of threat protection solutions categorization", OfficialFR: "Traiter le cas particulier de la catégorisation des solutions de protection contre les menaces", Section: "Centralized management agents", Automatable: false, Rationale: "Categorization decision, organizational"},
	{Code: "R51", Title: "Implement a WSUS architecture preserving segregation", OfficialFR: "Mettre en œuvre une architecture WSUS permettant de préserver le cloisonnement", Section: "Centralized management agents", Automatable: true},

	// === Section 3.7 — Network communications ===
	{Code: "R52", Title: "Secure network communication protocols used by Tier 0 resources", OfficialFR: "Sécuriser les protocoles de communication réseau utilisés par les ressources du Tier 0", Section: "Network communications", Automatable: true},
	{Code: "R53", Title: "Filter network flows between Tier 0 and uncontrolled networks", OfficialFR: "Filtrer les flux réseau entre le Tier 0 et les réseaux non maîtrisés", Section: "Network communications", Automatable: false, Rationale: "Network firewall configuration, not auditable from AD"},
	{Code: "R54", Title: "Filter network flows between Tier 0 and the rest of the IS", OfficialFR: "Filtrer les flux réseau entre le Tier 0 et le reste du SI", Section: "Network communications", Automatable: false, Rationale: "Network firewall configuration, not auditable from AD"},

	// === Section 3.8 — Physical access ===
	{Code: "R55", Title: "Pay particular attention to physical security of Tier 0 resources", OfficialFR: "Prêter une attention particulière à la sécurité physique des ressources du Tier 0", Section: "Physical access", Automatable: false, Rationale: "Physical security control, not auditable from AD"},
	{Code: "R56", Title: "Deploy RODCs when physical security cannot be ensured", OfficialFR: "Déployer des RODC lorsque la sécurité physique n'est pas assurée", Section: "Physical access", Automatable: true},
	{Code: "R57", Title: "Apply RODC hardening recommendations", OfficialFR: "Appliquer les recommandations de sécurisation des RODC", Section: "Physical access", Automatable: true},

	// === Section 3.9 — AD organizational unit hierarchy ===
	{Code: "R58", Title: "Create an organizational unit grouping Tier 0 objects", OfficialFR: "Créer une unité organisationnelle réunissant les objets du Tier 0", Section: "AD organizational unit hierarchy", Automatable: true},
	{Code: "R59", Title: "Restrict security policies applicable to the Tier 0 organizational unit", OfficialFR: "Restreindre les stratégies de sécurité applicables à l'unité organisationnelle du Tier 0", Section: "AD organizational unit hierarchy", Automatable: true},

	// === Section 3.11 — Cloud usage attention points ===
	{Code: "R60", Title: "Identify Tier 0 attack paths inherent to Cloud", OfficialFR: "Identifier les chemins d'attaque du Tier 0 inhérents au Cloud", Section: "Cloud usage", Automatable: false, Rationale: "Cloud architecture review, requires Azure/M365 deep audit"},

	// === Section 4 — NTLM and Kerberos dangers for IS segregation ===
	{Code: "R61", Title: "Address specific reusability risks of NTLM hashes and Kerberos secrets", OfficialFR: "Traiter les risques spécifiques de réutilisabilité des condensats NTLM et des secrets Kerberos", Section: "NTLM and Kerberos hardening", Automatable: true},
	{Code: "R62", Title: "Use Windows Defender Credential Guard only as defense in depth", OfficialFR: "Utiliser WDCG uniquement dans une démarche de défense en profondeur", Section: "NTLM and Kerberos hardening", Automatable: true},
	{Code: "R63", Title: "Do not use Windows Defender Remote Credential Guard between heterogeneous trust zones", OfficialFR: "Ne pas utiliser WDRCG entre zones de confiance hétérogènes", Section: "NTLM and Kerberos hardening", Automatable: false, Rationale: "v3.1.18 — niche (only relevant when WDRCG is deployed across trust zones); requires runtime trust-zone classification not derivable from AD alone"},
	{Code: "R64", Title: "Frame and restrict connections to less trusted resources", OfficialFR: "Encadrer et restreindre la connexion à des ressources de moindre confiance", Section: "NTLM and Kerberos hardening", Automatable: false, Rationale: "Operational practice, not directly auditable from AD"},
	{Code: "R65", Title: "Address risks inherent to Kerberos delegations", OfficialFR: "Traiter les risques inhérents aux délégations Kerberos", Section: "NTLM and Kerberos hardening", Automatable: true},
	{Code: "R66", Title: "Preserve Kerberos pre-authentication for Tier 0 accounts", OfficialFR: "Préserver la préauth. Kerberos pour les comptes de Tier 0", Section: "NTLM and Kerberos hardening", Automatable: true},
	{Code: "R67", Title: "Address risks inherent to absence of Kerberos pre-authentication", OfficialFR: "Traiter les risques inhérents à l'absence de préauth. Kerberos", Section: "NTLM and Kerberos hardening", Automatable: true},
	{Code: "R67-", Title: "Reduce the scope of reusable secrets exposed by absence of Kerberos pre-authentication", OfficialFR: "Réduire la portée des secrets réutilisables exposés par l'absence de préauth. Kerberos", Section: "NTLM and Kerberos hardening", Automatable: true},
	{Code: "R68", Title: "Enable Kerberos armoring on Tier 0 systems", OfficialFR: "Activer le blindage Kerberos sur les systèmes du Tier 0", Section: "NTLM and Kerberos hardening", Automatable: true},
	{Code: "R69", Title: "Forbid SPN exposure of reusable Tier 0 secrets", OfficialFR: "Proscrire l'exposition par SPN de secrets du Tier 0 réutilisables", Section: "NTLM and Kerberos hardening", Automatable: true},
	{Code: "R70", Title: "Address risks inherent to SPN exposure of reusable secrets", OfficialFR: "Traiter les risques inhérents à l'exposition par SPN de secrets réutilisables", Section: "NTLM and Kerberos hardening", Automatable: true},
	{Code: "R70-", Title: "Reduce the scope of reusable secrets exposed by SPN", OfficialFR: "Réduire la portée des secrets réutilisables exposés par SPN", Section: "NTLM and Kerberos hardening", Automatable: true},
	{Code: "R71", Title: "Forbid NTLM authentication for Tier 0 accounts", OfficialFR: "Interdire l'authentification NTLM des comptes du Tier 0", Section: "NTLM and Kerberos hardening", Automatable: true},
	{Code: "R72", Title: "Harden NTLM configuration on systems", OfficialFR: "Durcir la configuration de NTLM sur les systèmes", Section: "NTLM and Kerberos hardening", Automatable: true},
	{Code: "R73", Title: "Block outbound NTLM traffic from Tier 0 systems", OfficialFR: "Bloquer le trafic NTLM sortant depuis les systèmes du Tier 0", Section: "NTLM and Kerberos hardening", Automatable: true},
	{Code: "R74+", Title: "Block outbound NTLM traffic from all IS systems that allow it", OfficialFR: "Bloquer le trafic NTLM sortant depuis tous les systèmes du SI qui le permettent", Section: "NTLM and Kerberos hardening", Automatable: true},
	{Code: "R75", Title: "Protect Tier 0 LDAP services against NTLM relays", OfficialFR: "Protéger les services LDAP du Tier 0 contre les relais NTLM", Section: "NTLM and Kerberos hardening", Automatable: true},
	{Code: "R76", Title: "Protect Tier 0 SMB services against NTLM relays", OfficialFR: "Protéger les services SMB du Tier 0 contre les relais NTLM", Section: "NTLM and Kerberos hardening", Automatable: true},
	{Code: "R77", Title: "Protect Tier 0 web services against NTLM relays", OfficialFR: "Protéger les services Web du Tier 0 contre les relais NTLM", Section: "NTLM and Kerberos hardening", Automatable: false, Rationale: "v3.1.18 — IIS-side configuration (Extended Protection for Authentication, channel binding) lives outside AD/SYSVOL"},

	// === Section 5 — Administration architecture and pooling ===
	{Code: "R78", Title: "Frame and restrict use of remote connection clients", OfficialFR: "Encadrer et restreindre l'utilisation des clients de connexion distante", Section: "Administration architecture", Automatable: false, Rationale: "Operational practice, not directly auditable from AD"},
	{Code: "R79", Title: "Harden remote connection clients whose security policies allow use", OfficialFR: "Durcir les clients de connexion distante dont les politiques de sécurité autorisent l'usage", Section: "Administration architecture", Automatable: true},
	{Code: "R80", Title: "Administer Tier 0 from physically dedicated administration workstations (PAW)", OfficialFR: "Administrer le Tier 0 depuis des postes d'administration physiquement dédiés", Section: "Administration architecture", Automatable: false, Rationale: "Physical workstation inventory, not auditable from AD"},
	{Code: "R80-", Title: "Frame the pooling of Tier 0 administration workstations", OfficialFR: "Encadrer la mutualisation des postes d'administration du Tier 0", Section: "Administration architecture", Automatable: false, Rationale: "Workstation policy, not auditable from AD"},
	{Code: "R80+", Title: "Extend the principle of non-pooling to all administration workstations", OfficialFR: "Étendre le principe de non mutualisation des postes d'administration", Section: "Administration architecture", Automatable: false, Rationale: "Workstation policy, not auditable from AD"},
	{Code: "R81", Title: "Categorize multi-tier workstations into appropriate Tiers", OfficialFR: "Catégoriser les postes multiniveaux dans les Tiers adéquats", Section: "Administration architecture", Automatable: false, Rationale: "Categorization decision, organizational"},
	{Code: "R82", Title: "Restrict access to less trusted zone resources from Tier 0", OfficialFR: "Restreindre l'accès aux ressources de zones de moindre confiance depuis le Tier 0", Section: "Administration architecture", Automatable: true},
	{Code: "R83", Title: "Restrict authorized connection accounts for display redirection", OfficialFR: "Restreindre les comptes de connexion autorisés pour le déport d'affichage", Section: "Administration architecture", Automatable: true},
	{Code: "R84", Title: "Respect placement rules for intermediate administration resources", OfficialFR: "Respecter les règles de positionnement des ressources d'administration intermédiaires", Section: "Administration architecture", Automatable: false, Rationale: "Architecture placement, organizational"},
	{Code: "R85", Title: "Avoid deploying an administration forest", OfficialFR: "Éviter le déploiement d'une forêt d'administration", Section: "Administration architecture", Automatable: false, Rationale: "Architecture decision, organizational"},
	{Code: "R86", Title: "Ensure segregation of any administration forest deployed", OfficialFR: "Assurer le cloisonnement d'une éventuelle forêt d'administration AD", Section: "Administration architecture", Automatable: true},
	{Code: "R87", Title: "Apply ANSSI ADMIN guide R15 and R15- recommendations with discernment", OfficialFR: "Appliquer les recommandations R15 et R15- du guide ADMIN avec discernement", Section: "Administration architecture", Automatable: false, Rationale: "Cross-reference to PA-022 ADMIN guide, manual review"},
	{Code: "R88", Title: "Apply ANSSI ADMIN guide R18 and R18- recommendations with discernment", OfficialFR: "Appliquer les recommandations R18 et R18- du guide ADMIN avec discernement", Section: "Administration architecture", Automatable: false, Rationale: "Cross-reference to PA-022 ADMIN guide, manual review"},
	{Code: "R89", Title: "Forbid Tier 0 administration remotely or while traveling", OfficialFR: "Interdire l'administration du Tier 0 à distance ou en nomadisme", Section: "Administration architecture", Automatable: false, Rationale: "Operational practice, not directly auditable from AD"},
	{Code: "R89-", Title: "Secure remote or traveling Tier 0 administration", OfficialFR: "Sécuriser l'administration à distance ou en nomadisme du Tier 0", Section: "Administration architecture", Automatable: false, Rationale: "v3.1.18 — requires runtime PAW/jump-host session inspection and VPN configuration audit, outside AD/SYSVOL scope"},
}
