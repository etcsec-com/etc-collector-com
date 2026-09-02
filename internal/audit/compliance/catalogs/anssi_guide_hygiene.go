package catalogs

// ANSSI Guide d'hygiène informatique — 42 mesures essentielles.
//
// Source officielle (vérifiée 2026-04-27 contre le PDF par pdftotext) :
//   https://messervices.cyber.gouv.fr/documents-guides/guide_hygiene_informatique_anssi.pdf
// Référence : Guide ANSSI-GP-042, 2nde édition, septembre 2017.
// Document complet : "Guide d'hygiène informatique : Renforcer la sécurité de
// son système d'information en 42 mesures".
//
// IMPORTANT — Réécrit en v3.1.16 après fact-check externe contre le PDF
// officiel. La version précédente (v3.0.x à v3.1.15) avait au moins 25 titres
// faux sur les 42 (numérotation décalée à partir de M16, probable mélange
// entre l'édition 2013 [40 mesures] et 2017 [42 mesures]). Chaque titre
// ci-dessous est aligné byte-for-byte avec le PDF officiel.
//
// Les codes utilisent le préfixe "M" (Mesure) suivi du numéro officiel 1-42.
// Cette convention "M<n>" est notre choix d'identifiant pour la cohérence
// avec les autres catalogs (PA-099 utilise "R<n>", DISA utilise "V-<n>",
// etc.). Le numéro <n> matche exactement le numéro officiel ANSSI.

func init() {
	register(&Catalog{
		Framework: "ANSSI_GUIDE_HYGIENE",
		Source:    "https://messervices.cyber.gouv.fr/documents-guides/guide_hygiene_informatique_anssi.pdf",
		Version:   "ANSSI-GP-042 2nde édition (09/2017) — 42 mesures",
		FetchedAt: "2026-04-27",
		Controls:  anssiGuideHygieneControls,
	})
}

// Automatable classification methodology:
//   - true  = the measure prescribes something verifiable from LDAP, GPO XMLs
//     in SYSVOL, or AD attributes (e.g. inventory of privileged accounts,
//     password policy, audit log activation, EOL of DC OS)
//   - false = organizational, contractual, physical, network-architecture
//     or out-of-AD-scope controls (e.g. HR procedures, hardware procurement,
//     mailbox security, awareness training)
//
// The classification was reviewed against the body of each measure in the
// official PDF, not just the title.
var anssiGuideHygieneControls = []ControlSpec{
	// === I — Sensibiliser et former ===
	{Code: "M1", Title: "Train operational teams in IS security", OfficialFR: "Former les équipes opérationnelles à la sécurité des systèmes d'information", Section: "Awareness and training", Automatable: false, Rationale: "Training program, organizational"},
	{Code: "M2", Title: "Raise users awareness of basic IT security best practices", OfficialFR: "Sensibiliser les utilisateurs aux bonnes pratiques élémentaires de sécurité informatique", Section: "Awareness and training", Automatable: false, Rationale: "User awareness program, organizational"},
	{Code: "M3", Title: "Manage the risks tied to IT outsourcing", OfficialFR: "Maîtriser les risques de l'infogérance", Section: "Awareness and training", Automatable: false, Rationale: "Outsourcing contract framework, organizational"},

	// === II — Connaître le système d'information ===
	{Code: "M4", Title: "Identify the most sensitive information and servers and maintain a network diagram", OfficialFR: "Identifier les informations et serveurs les plus sensibles et maintenir un schéma du réseau", Section: "Knowing the IS", Automatable: false, Rationale: "Asset inventory exercise, organizational"},
	{Code: "M5", Title: "Maintain an exhaustive and up-to-date inventory of privileged accounts", OfficialFR: "Disposer d'un inventaire exhaustif des comptes privilégiés et le maintenir à jour", Section: "Knowing the IS", Automatable: true, Rationale: "Verifiable from LDAP enumeration of privileged groups"},
	{Code: "M6", Title: "Organize procedures for arrival, departure and change of duties for users", OfficialFR: "Organiser les procédures d'arrivée, de départ et de changement de fonction des utilisateurs", Section: "Knowing the IS", Automatable: false, Rationale: "HR/IAM joiner-mover-leaver process, organizational"},

	// === III — Authentifier et contrôler les accès ===
	{Code: "M7", Title: "Allow only managed equipment to connect to the entity's network", OfficialFR: "Autoriser la connexion au réseau de l'entité aux seuls équipements maîtrisés", Section: "Authentication and access control", Automatable: false, Rationale: "Network access control / NAC, outside AD scope"},
	{Code: "M8", Title: "Identify each individual accessing the system by name and distinguish user/administrator roles", OfficialFR: "Identifier nommément chaque personne accédant au système et distinguer les rôles utilisateur/administrateur", Section: "Authentication and access control", Automatable: true, Rationale: "Verifiable from LDAP: dedicated admin accounts, naming convention, group membership"},
	{Code: "M9", Title: "Allocate the right permissions on the IS sensitive resources", OfficialFR: "Attribuer les bons droits sur les ressources sensibles du système d'information", Section: "Authentication and access control", Automatable: true, Rationale: "Verifiable from LDAP: ACLs on sensitive containers, group memberships"},
	{Code: "M10", Title: "Define and verify rules for choosing and sizing passwords", OfficialFR: "Définir et vérifier des règles de choix et de dimensionnement des mots de passe", Section: "Authentication and access control", Automatable: true, Rationale: "Verifiable from LDAP password policy + PSO"},
	{Code: "M11", Title: "Protect passwords stored on systems", OfficialFR: "Protéger les mots de passe stockés sur les systèmes", Section: "Authentication and access control", Automatable: true, Rationale: "Verifiable via GPO (LM hash, reversible encryption, NTLM hardening)"},
	{Code: "M12", Title: "Change default authentication settings on equipment and services", OfficialFR: "Changer les éléments d'authentification par défaut sur les équipements et services", Section: "Authentication and access control", Automatable: true, Rationale: "Verifiable from LDAP (default Administrator account state, default service accounts)"},
	{Code: "M13", Title: "Prefer strong authentication where possible", OfficialFR: "Privilégier lorsque c'est possible une authentification forte", Section: "Authentication and access control", Automatable: true, Rationale: "Verifiable from LDAP (smart card required, Protected Users group, MFA enrollment in Entra)"},

	// === IV — Sécuriser les postes ===
	{Code: "M14", Title: "Implement a minimum security baseline across the entire endpoint fleet", OfficialFR: "Mettre en place un niveau de sécurité minimal sur l'ensemble du parc informatique", Section: "Endpoint security", Automatable: false, Rationale: "Endpoint hardening baseline, requires per-endpoint configuration audit"},
	{Code: "M15", Title: "Protect against threats related to the use of removable media", OfficialFR: "Se protéger des menaces relatives à l'utilisation de supports amovibles", Section: "Endpoint security", Automatable: false, Rationale: "Endpoint USB/media policy, requires per-endpoint audit"},
	{Code: "M16", Title: "Use a centralized management tool to homogenize security policies", OfficialFR: "Utiliser un outil de gestion centralisée afin d'homogénéiser les politiques de sécurité", Section: "Endpoint security", Automatable: false, Rationale: "Tooling deployment (SCCM, Intune), outside AD scope"},
	{Code: "M17", Title: "Activate and configure the local firewall on workstations", OfficialFR: "Activer et configurer le pare-feu local des postes de travail", Section: "Endpoint security", Automatable: true, Rationale: "Verifiable via GPO firewall settings deployed through SYSVOL"},
	{Code: "M18", Title: "Encrypt sensitive data sent over the internet", OfficialFR: "Chiffrer les données sensibles transmises par voie Internet", Section: "Endpoint security", Automatable: false, Rationale: "Application-layer encryption, outside AD scope"},

	// === V — Sécuriser le réseau ===
	{Code: "M19", Title: "Segment the network and partition between zones", OfficialFR: "Segmenter le réseau et mettre en place un cloisonnement entre ces zones", Section: "Network security", Automatable: false, Rationale: "Network segmentation review, requires network audit"},
	{Code: "M20", Title: "Ensure security of Wi-Fi access networks and separation of usage", OfficialFR: "S'assurer de la sécurité des réseaux d'accès Wi-Fi et de la séparation des usages", Section: "Network security", Automatable: false, Rationale: "Wireless network configuration, outside AD scope"},
	{Code: "M21", Title: "Use secure protocols whenever they exist", OfficialFR: "Utiliser des protocoles sécurisés dès qu'ils existent", Section: "Network security", Automatable: true, Rationale: "Verifiable from GPO/LDAP: SMB signing, LDAP signing, TLS versions, NTLMv1"},
	{Code: "M22", Title: "Implement a secured Internet access gateway", OfficialFR: "Mettre en place une passerelle d'accès sécurisé à Internet", Section: "Network security", Automatable: false, Rationale: "Proxy/gateway architecture, outside AD scope"},
	{Code: "M23", Title: "Partition the services exposed to the Internet from the rest of the IS", OfficialFR: "Cloisonner les services visibles depuis Internet du reste du système d'information", Section: "Network security", Automatable: false, Rationale: "DMZ architecture, outside AD scope"},
	{Code: "M24", Title: "Protect the corporate email", OfficialFR: "Protéger sa messagerie professionnelle", Section: "Network security", Automatable: false, Rationale: "Mail server configuration (SPF/DKIM/DMARC, antispam), outside AD scope"},
	{Code: "M25", Title: "Secure dedicated network interconnections with partners", OfficialFR: "Sécuriser les interconnexions réseau dédiées avec les partenaires", Section: "Network security", Automatable: false, Rationale: "VPN/B2B network configuration, outside AD scope"},
	{Code: "M26", Title: "Control and protect access to server rooms and technical premises", OfficialFR: "Contrôler et protéger l'accès aux salles serveurs et aux locaux techniques", Section: "Network security", Automatable: false, Rationale: "Physical access control, not auditable from AD"},

	// === VI — Sécuriser l'administration ===
	{Code: "M27", Title: "Forbid Internet access from workstations or servers used for IS administration", OfficialFR: "Interdire l'accès à Internet depuis les postes ou serveurs utilisés pour l'administration du système d'information", Section: "Administration security", Automatable: false, Rationale: "Workstation network policy, requires per-endpoint audit"},
	{Code: "M28", Title: "Use a dedicated and partitioned network for IS administration", OfficialFR: "Utiliser un réseau dédié et cloisonné pour l'administration du système d'information", Section: "Administration security", Automatable: false, Rationale: "Network architecture, outside AD scope"},
	{Code: "M29", Title: "Limit administration rights on workstations to strict operational need", OfficialFR: "Limiter au strict besoin opérationnel les droits d'administration sur les postes de travail", Section: "Administration security", Automatable: true, Rationale: "Verifiable via GPO Restricted Groups + 'Local Administrators' membership"},

	// === VII — Gérer le nomadisme ===
	{Code: "M30", Title: "Take physical security measures for nomadic devices", OfficialFR: "Prendre des mesures de sécurisation physique des terminaux nomades", Section: "Mobility management", Automatable: false, Rationale: "Physical security policy, outside AD scope"},
	{Code: "M31", Title: "Encrypt sensitive data, in particular on devices that may be lost", OfficialFR: "Chiffrer les données sensibles, en particulier sur le matériel potentiellement perdable", Section: "Mobility management", Automatable: false, Rationale: "Endpoint encryption (BitLocker / FileVault), per-endpoint audit"},
	{Code: "M32", Title: "Secure the network connection of workstations used in nomadic situations", OfficialFR: "Sécuriser la connexion réseau des postes utilisés en situation de nomadisme", Section: "Mobility management", Automatable: false, Rationale: "VPN client configuration, outside AD scope"},
	{Code: "M33", Title: "Adopt security policies dedicated to mobile terminals", OfficialFR: "Adopter des politiques de sécurité dédiées aux terminaux mobiles", Section: "Mobility management", Automatable: false, Rationale: "MDM policy (Intune, MobileIron), outside AD scope"},

	// === VIII — Maintenir à jour le système d'information ===
	{Code: "M34", Title: "Define an update policy for IS components", OfficialFR: "Définir une politique de mise à jour des composants du système d'information", Section: "Patch management", Automatable: false, Rationale: "Update process and policy document, organizational"},
	{Code: "M35", Title: "Anticipate the end of maintenance of software and systems and limit software dependencies", OfficialFR: "Anticiper la fin de la maintenance des logiciels et systèmes et limiter les adhérences logicielles", Section: "Patch management", Automatable: true, Rationale: "Verifiable from LDAP: DC OS version, schema version, functional level — flag obsolete OS"},

	// === IX — Superviser, auditer, réagir ===
	{Code: "M36", Title: "Activate and configure logs of the most important components", OfficialFR: "Activer et configurer les journaux des composants les plus importants", Section: "Monitoring", Automatable: true, Rationale: "Verifiable via GPO advanced audit policy + Security log size"},
	{Code: "M37", Title: "Define and apply a backup policy for critical components", OfficialFR: "Définir et appliquer une politique de sauvegarde des composants critiques", Section: "Monitoring", Automatable: false, Rationale: "Backup process and tooling, outside AD scope"},
	{Code: "M38", Title: "Conduct regular security checks and audits, then apply the corrective actions", OfficialFR: "Procéder à des contrôles et audits de sécurité réguliers puis appliquer les actions correctives associées", Section: "Monitoring", Automatable: false, Rationale: "Audit cadence, organizational"},
	{Code: "M39", Title: "Designate a security officer for the IS and make them known to staff", OfficialFR: "Désigner un référent en sécurité des systèmes d'information et le faire connaître auprès du personnel", Section: "Monitoring", Automatable: false, Rationale: "Org chart assignment, organizational"},
	{Code: "M40", Title: "Define a security incident management procedure", OfficialFR: "Définir une procédure de gestion des incidents de sécurité", Section: "Monitoring", Automatable: false, Rationale: "Incident response procedure document, organizational"},

	// === X — Pour aller plus loin ===
	{Code: "M41", Title: "Conduct a formal risk analysis", OfficialFR: "Mener une analyse de risques formelle", Section: "Going further", Automatable: false, Rationale: "Risk assessment exercise (EBIOS, ISO 27005), organizational"},
	{Code: "M42", Title: "Prefer the use of products and services qualified by the ANSSI", OfficialFR: "Privilégier l'usage de produits et de services qualifiés par l'ANSSI", Section: "Going further", Automatable: false, Rationale: "Procurement decision, organizational"},
}
