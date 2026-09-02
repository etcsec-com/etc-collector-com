# Compliance — frameworks supportés et structure JSON

> **Correction 2026-09-02** : la table ci-dessous listait encore l'état
> v3.1.0–v3.1.2 (`ANSSI_PA022`, `ANSSI_PR001`, `ANSSI_40_MESURES`,
> `ANSSI_PA038`) comme "supportés en v3.1.2" — présent tense — alors que la
> section [Frameworks ANSSI **retirés** en v3.1.11](#frameworks-anssi-retirés-en-v3111)
> plus bas dans ce même fichier dit que ces quatre labels ont été retirés.
> Les deux ne peuvent pas être vrais en même temps ; la table ci-dessous est
> corrigée pour refléter l'état réel du binaire v3.2.0, confirmé en direct
> (`complianceScores[].framework` d'un audit réel liste exactement ces 9
> valeurs). Le reste du fichier (mappings détaillés par article/contrôle)
> reste globalement valide pour `ANSSI_PA099` et n'a pas été ré-audité ligne
> à ligne dans ce passage.

Depuis **v3.1.16**, chaque finding peut être rattaché à un ou plusieurs contrôles de framework compliance, et le rapport JSON inclut un score par framework. v3.2.0 ship **9 frameworks**, tous référencés contre leur identifiant de publication officiel — voir aussi la table équivalente dans [`README.md`](../../README.md#compliance-frameworks) :

| Framework | ID interne | Contrôles vérifiés |
|---|---|---|
| ANSSI-PA-099 (Active Directory) | `ANSSI_PA099` | 90 |
| ANSSI-BP-039 (Windows 10 hardening / virtualisation) | `ANSSI_BP039` | 3 |
| ANSSI Guide d'hygiène informatique | `ANSSI_GUIDE_HYGIENE` | 18 |
| HDS v1.1 | `HDS_v1_1` | 40 |
| RGPD article 32 | `RGPD` | 21 |
| NIS2 (transposition FR loi 2024-449) | `NIS2_FR` | 42 |
| CIS Controls v8.1 | `CIS_v8` | 19 |
| NIST SP 800-53 Rev.5 | `NIST_800_53` | 20 |
| DISA STIG (AD Domain V3R3) | `DISA_STIG` | 8 |

`ANSSI_PA022`, `ANSSI_PR001`, `ANSSI_40_MESURES` et `ANSSI_PA038` sont des
labels **historiques**, retirés en v3.1.11 (voir plus bas) — ne pas les
utiliser dans du code ou de la config neufs.

**Indice de maturité ANSSI** (composite, 5 axes 0-5) calculé pour `ANSSI_PA099` uniquement, sortie dans `summary.complianceScores[].maturityAxes[]`.

**NIS2 — détecteurs mappés par article** (mappings sur détecteurs existants, aucun nouveau détecteur) :

| Article NIS2 | Thème | Détecteurs couverts |
|---|---|---|
| Art.21(2)(a) | IAM & politiques sécurité | `ANSSI_R1_*`, `WEAK_PASSWORD_POLICY`, `ANSSI_R2_*`, `EXCESSIVE_PRIVILEGED_ACCOUNTS` |
| Art.21(2)(b) | Gestion des incidents / logging | `ANSSI_R4_LOGGING`, `ANSSI_R38_*`, `ANSSI_R39_*`, `AUDIT_LOG_RETENTION_SHORT`, `PA038_PS_*_LOGGING_*` |
| Art.21(2)(c) | Continuité & backup | `BACKUP_AD_NOT_VERIFIED`, `HDS_5_8_DR_PLAN_MISSING`, `ANSSI_R28_KRBTGT_NOT_ROTATED` |
| Art.21(2)(e) | Sécurité systèmes & réseaux | 10 détecteurs PA-038 (RDP, LLMNR, SMB1, UNC, Defender, Firewall, WSUS, Print, Zerologon) |
| Art.21(2)(h) | Cryptographie | `WEAK_ENCRYPTION_DES`, `WEAK_ENCRYPTION_RC4`, `ANSSI_R23_LM_HASH_*`, `SMB_SIGNING_DISABLED`, `LDAP_CHANNEL_BINDING_DISABLED`, `NTLMV1_ALLOWED`, `PA038_BITLOCKER_*` |
| Art.21(2)(i) | Contrôle d'accès | `ANSSI_R5_SEGREGATION`, `DCSYNC_CAPABLE`, `UNCONSTRAINED_DELEGATION`, `ANSSI_R14_*`, `ADMIN_SD_HOLDER_MODIFIED`, `PA038_NET_SESSION_*` |
| Art.21(2)(j) | MFA | `ANSSI_R3_STRONG_AUTH`, `MFA_NOT_ENFORCED`, `ANSSI_R3_1_SMARTCARD_*`, `ASREP_ROASTING_RISK` |

**Contrôles NIS2 infaisables (justifiés)** : Art.21(2)(d) supply chain (SBOM/inventaire fournisseurs, hors AD) ; Art.21(2)(f) évaluation d'efficacité (organisationnel) ; Art.21(2)(g) formation/sensibilisation (organisationnel).

**PA-038 — contrôles infaisables (justifiés)** : antivirus tiers / config Defender avancée (hors Registry.pol standard) ; chiffrement disque non-Windows (hors AD/GPO, nécessite inventaire IT).

CIS, NIST 800-53 et DISA STIG sont couverts depuis v3.2.0 (table ci-dessus).
Toujours **non couverts** au 2026-09-02 : PCI DSS, SOC 2, ISO 27001:2022, HIPAA, DORA.

> Contrôles infaisables PA-022 (justifiés) : R37.1 AppLocker XML detail (parser SYSVOL XML manquant, planifié v3.2.0) ; PR-001 §3.1 PAW, §3.2 RDP audit, §4.1 JEA → nécessitent un agent EDR ou des logs hors AD.

---

## Structure JSON

### `Finding.compliance[]`

Chaque finding gagne un champ optionnel `compliance` qui liste les contrôles satisfaits ou violés par ce détecteur. `omitempty` → les findings non-compliance restent inchangés.

```json
{
  "type": "DCSYNC_CAPABLE",
  "severity": "critical",
  "category": "advanced",
  "title": "DCSync Rights Detected",
  "count": 3,
  "compliance": [
    { "framework": "ANSSI_PA022", "control": "R12", "severity": "critical" },
    { "framework": "HDS_v1_1",    "control": "5.6" },
    { "framework": "NIS2_FR",     "control": "Art.21(2)(i)" }
  ]
}
```

Champ `severity` dans la mapping est **optionnel** : il override la severity globale du finding dans le contexte de ce framework spécifique (un finding "low" en hygiène peut être "critical" sous HDS).

### `summary.complianceScores[]`

Le rapport global contient un tableau de scores par framework :

```json
{
  "audit": {
    "summary": {
      "objects": { ... },
      "risk": { "score": 39.6, "rating": "high", ... },
      "complianceScores": [
        {
          "framework": "ANSSI_PA022",
          "score": 72.4,
          "rating": "medium",
          "controlsTotal": 14,
          "controlsPassed": 10,
          "controlsFailed": 4,
          "failedControls": ["R1", "R12", "R13", "R24"]
        },
        {
          "framework": "HDS_v1_1",
          "score": 81.8,
          "rating": "low",
          "controlsTotal": 11,
          "controlsPassed": 9,
          "controlsFailed": 2,
          "failedControls": ["5.4", "5.6"]
        },
        {
          "framework": "RGPD",
          "score": 75.0,
          "rating": "medium",
          "controlsTotal": 4,
          "controlsPassed": 3,
          "controlsFailed": 1,
          "failedControls": ["art.32(1)(a)"]
        }
      ]
    }
  }
}
```

**Sémantique du score** : 0-100, **plus c'est haut mieux c'est** (% de contrôles vérifiés sans violation). Inverse du score de risque global (où 0 = parfait, 100 = critique).

**Ratings** :
- `excellent` : >= 95
- `low` : 80-94 (= faible risque conformité)
- `medium` : 60-79
- `high` : 40-59
- `critical` : < 40

**Dénominateur (`controlsTotal`)** : nombre de contrôles distincts pour lesquels ETC ship au moins un détecteur. Si ETC ne vérifie pas un contrôle, il n'est pas compté (évite de gonfler artificiellement le score).

**Contrôles failed** : tout contrôle dont au moins un détecteur ETC a produit un finding actif (`count > 0`).

---

## Scope profiles compliance

Trois profils prédéfinis pour limiter l'audit aux détecteurs d'un framework :

| Profile | Effet |
|---|---|
| `compliance-anssi` | n'exécute que les détecteurs taggés ANSSI_PA022 (29) |
| `compliance-hds` | n'exécute que les détecteurs taggés HDS_v1_1 (29) |
| `compliance-rgpd` | n'exécute que les détecteurs taggés RGPD (15) |

Le profil `compliance` (existant) reste agnostique des frameworks et lance toutes les catégories `compliance` + `azureCompliance`.

### CLI

```bash
etc-collector audit ad \
  --ldap-url ldaps://dc01:636 ... \
  --scope-profile compliance-anssi \
  -o anssi.json
```

### YAML server mode

```yaml
audit:
  scope:
    profile: compliance-hds
```

### SaaS daemon (`RUN_AUDIT_AD`)

```json
{ "params": { "scope": { "profile": "compliance-rgpd" } } }
```

### Env var

```bash
AUDIT_PROFILE=compliance-anssi etc-collector audit ad ...
```

### Découverte

```bash
etc-collector audit list
# → liste les profils dont compliance-anssi (29 detectors), compliance-hds (29), compliance-rgpd (15)
```

Combinable avec `--scope-include-categories` / `--scope-exclude-detectors` (sémantique cumulative comme tout scope).

---

## Couverture détaillée par framework

### Frameworks ANSSI

#### Publications ANSSI référencées (toutes vérifiées contre [bibliotex/anssi.bib](https://github.com/ANSSI-FR/bibliotex/blob/main/anssi.bib))

| Label framework dans le JSON | Publication officielle | Date | URL cyber.gouv.fr |
|---|---|---|---|
| `ANSSI_PA099` | **ANSSI-PA-099 v1.0** — Recommandations pour l'administration sécurisée des SI reposant sur Microsoft Active Directory | 02/10/2023 | [PDF officiel](https://messervices.cyber.gouv.fr/documents-guides/anssi-guide-admin_securisee_si_ad_v1-0%20(3).pdf) |
| `ANSSI_BP039` | **ANSSI-BP-039 v1.0** — Mise en œuvre des fonctionnalités de sécurité de Windows 10 reposant sur la virtualisation | 08/11/2017 | [PDF officiel](https://cyber.gouv.fr/sites/default/files/2017/11/np_securisation_windows10_securite_reposant_sur_la_virtualisation_v1.pdf) |
| `ANSSI_GUIDE_HYGIENE` | **ANSSI-GP-042 v2.0** — Guide d'hygiène informatique : renforcer la sécurité de son SI en 42 mesures | 09/2017 (2nde éd.) | [PDF officiel](https://messervices.cyber.gouv.fr/documents-guides/guide_hygiene_informatique_anssi.pdf) |

#### ✅ Fidélité auditeur ANSSI (v3.1.16+)

Les codes utilisés dans `compliance[].control` pour les frameworks ANSSI matchent **byte-for-byte** les codes des publications officielles :

- `ANSSI_PA099` : R1 à R89 + sous-recos `+/-` (R14+, R19+, R25+, R30-, R67-, R70-, R74+, R80-, R80+, R89-) — **95 controls** vérifiés contre la "Liste des recommandations" p. 150-152 du PDF officiel
- `ANSSI_BP039` : R1 à R15 + sous-recos `*`/`**` (R4*, R4**, R7*, R7**, R10*, R10**) — **21 controls** vérifiés contre le PDF officiel p. 48
- `ANSSI_GUIDE_HYGIENE` : M1 à M42 (numérotation 1:1 avec les mesures officielles 1 à 42) — vérifié contre la table des matières du PDF officiel

Chaque control du catalog interne expose son `OfficialFR` (titre français exact), permettant à un auditeur ANSSI de croiser le report ETC avec la publication source. La commande `etc-collector compliance verify --framework ANSSI_PA099` affiche les métadonnées (URL source, version, date du dernier fact-check, coverage).

#### Historique (v3.1.0 à v3.1.15)

Avant v3.1.16, certains catalogs ANSSI contenaient des **erreurs de fidélité** :

- `ANSSI_BP039` utilisait des codes **inventés** (`Secure-Boot`, `BitLocker`, `LSA-Protection`...) qui n'existaient dans aucune publication ANSSI
- `ANSSI_GUIDE_HYGIENE` avait 25 titres faux sur 42 (mélange entre éditions 2013 et 2017)
- `ANSSI_PA099` contenait ~14 mappings "stretched" (ex : MFA détecteurs mappés sur R66 = Kerberos pre-auth Tier 0, sans rapport)

Ces problèmes ont été **intégralement corrigés en v3.1.16** par fact-check externe contre les PDFs officiels (cf. `internal/audit/compliance/SOURCES.md` et le test `TestANSSIControlsHaveOfficialReference` qui empêche la régression).

#### Frameworks ANSSI **retirés** en v3.1.11

- `ANSSI_PA022` (utilisé v3.1.0–v3.1.10) — PA-022 v3.0 existe ([lien](https://messervices.cyber.gouv.fr/documents-guides/anssi-guide-admin_securisee_si_v3-0.pdf)) mais c'est un guide d'administration générique (R-codes vont jusqu'à R68+), **pas spécifique AD**. Les findings sont désormais tagués `ANSSI_PA099`.
- `ANSSI_PR001` — **N'EXISTE PAS** chez ANSSI (pas de série "PR-XXX"). Label maison retiré. Détecteurs `PR001_*` re-tagués sur `ANSSI_PA099`.
- `ANSSI_PA038` — **N'EXISTE PAS** chez ANSSI (BP-038 existe mais traite du DNS, sans rapport). Label maison retiré. Détecteurs `PA038_*` re-tagués sur `ANSSI_PA099` (et `ANSSI_BP039` pour BitLocker, LSA Protection, Credential Guard).
- `ANSSI_40_MESURES` — renommé `ANSSI_GUIDE_HYGIENE` pour matcher le titre officiel du document source.

#### ⚠️ Aucun framework ANSSI Azure / Entra ID

L'ANSSI **n'a publié aucun guide officiel** sur Azure / Microsoft 365 / Entra ID au 22/04/2026. PA-099 mentionne brièvement les déploiements hybrides mais ne couvre pas le cloud. Pour auditer la compliance Azure, utiliser `CIS_v8`, `NIST_800_53`, `NIS2_FR` ou `RGPD`.

#### Couverture thématique (numérotation R1-R39 interne)

| Thème (numérotation interne) | Détecteurs |
|---|---|
| R1 — Politique de mot de passe | `ANSSI_R1_PASSWORD_POLICY`, `PASSWORD_REVERSIBLE_ENCRYPTION`, `WEAK_PASSWORD_POLICY` |
| R2 — Comptes privilégiés | `ANSSI_R2_PRIVILEGED_ACCOUNTS`, `EXCESSIVE_PRIVILEGED_ACCOUNTS`, `PRIVILEGED_ACCOUNT_STALE`, `NOT_IN_PROTECTED_USERS` |
| R3 — Authentification forte | `ANSSI_R3_STRONG_AUTH`, `MFA_NOT_ENFORCED` |
| R4 — Logging / audit | `ANSSI_R4_LOGGING`, `AUDIT_LOG_RETENTION_SHORT` |
| R5 — Ségrégation environnements (tiering) | `ANSSI_R5_SEGREGATION` |
| R6 — Comptes inactifs | `ANSSI_R6_INACTIVE_ACCOUNTS` |
| R7 — Comptes stales non supprimés | `ANSSI_R7_STALE_ACCOUNTS_NOT_REMOVED` |
| R8 — Comptes service vs nominatifs | `ANSSI_R8_SERVICE_ACCOUNTS_AS_USERS` |
| R9 — Rotation secrets service | `ANSSI_R9_SERVICE_ACCOUNT_SECRET_ROTATION` |
| R10 — Pré-authentification Kerberos | `ASREP_ROASTING_RISK` |
| R11 — Protected Users | `ANSSI_R11_ADMINS_NOT_IN_PROTECTED_USERS` |
| R12 — DCSync | `DCSYNC_CAPABLE`, `REPLICATION_RIGHTS` |
| R13 — Délégation non contrainte | `UNCONSTRAINED_DELEGATION` |
| R14 — RBCD audit | `ANSSI_R14_RBCD_AUDIT` |
| R15 — Modèle en tiers (T0/T1/T2) | `ANSSI_R15_TIER_MODEL_VIOLATION` |
| R16 — AdminSDHolder | `ADMIN_SD_HOLDER_MODIFIED` |
| R17-R19, R23, R27-R39 | détecteurs `ANSSI_R17_*` à `ANSSI_R39_*` |
| R22 — NTLMv1 | `NTLMV1_ALLOWED` |
| R25 — SMB signing | `SMB_SIGNING_DISABLED` |
| R26 — LDAP channel binding | `LDAP_CHANNEL_BINDING_DISABLED` |
| R36 — LAPS | `LAPS_NOT_DEPLOYED` |
| Hardening DC (ex-PA038) | `PA038_RDP_NLA_NOT_REQUIRED`, `PA038_PS_*`, `PA038_LLMNR_ENABLED`, `PA038_WSUS_NOT_CONFIGURED`, etc. (préfixe historique conservé) |

#### `ANSSI_BP039` — Windows 10 hardening basé sur la virtualisation (v3.1.16+)

Réécriture complète en v3.1.16 contre le PDF officiel. Les anciens codes inventés (`LSA-Protection`, `Credential-Guard`, `BitLocker`) ont été remplacés par les vrais R-codes du document.

| Contrôle officiel | Titre | Détecteurs ETC |
|---|---|---|
| **R10** | Mettre en œuvre Credential Guard | `ANSSI_R35_CREDENTIAL_GUARD_OFF` |
| _R1-R9, R11-R15 + sous-recos `*`/`**`_ | (autres recos officielles, pas de detector ETC actuellement — chantier v3.1.17) | — |

**Note** : `ANSSI_R34_LSA_PROTECTION_OFF` et `PA038_BITLOCKER_NOT_REQUIRED` n'ont **plus** de mapping BP-039 en v3.1.16, car ces sujets ne sont pas dans le périmètre de la publication officielle BP-039. LSA Protection est mappée sur PA-099 R62 (Credential Guard defense in depth).

### HDS v1.1

| Exigence | Couvert | Détecteurs |
|---|---|---|
| 5.1.4 — Authentification forte | ✓ partiel (info) | `HDS_5_1_4_STRONG_AUTH` + `ANSSI_R3_STRONG_AUTH`, `MFA_NOT_ENFORCED` |
| 5.2 — Chiffrement transit | ✓ partiel (info) | `HDS_5_2_TLS_NOT_ENFORCED` + `LDAP_SIGNING_NOT_ENFORCED`, `WEAK_ENCRYPTION_RC4` |
| 5.3 — Chiffrement repos | ✓ | `ENCRYPTION_AT_REST_DISABLED` |
| 5.4 — Traçabilité accès données santé | ✓ | `HDS_5_4_LOG_ACCESS_TO_HEALTH_DATA` + `ANSSI_R4_LOGGING`, `AUDIT_LOG_RETENTION_SHORT`, `AUDIT_POLICY_INSUFFICIENT` |
| 5.5 — Politique de mot de passe | ✓ | `ANSSI_R1_PASSWORD_POLICY` + dérivés |
| 5.6 — Gestion comptes privilégiés | ✓ | `ANSSI_R2_*`, `R6`, `R8`, `R11`, `R12`, `DCSYNC_CAPABLE`, `REPLICATION_RIGHTS`, `VENDOR_ACCOUNT_UNMONITORED`, `PRIVILEGED_ACCESS_REVIEW_MISSING` |
| 5.7 — Sauvegarde + intégrité | ✓ | `BACKUP_AD_NOT_VERIFIED`, `AD_RECYCLE_BIN_DISABLED`, `NO_OFFLINE_BACKUP` |
| 5.8 — Plan de continuité (BCP) | ✓ | `HDS_5_8_DR_PLAN_MISSING` |
| 5.9 — Cloisonnement environnements | ✓ | `ANSSI_R5_SEGREGATION`, `ANSSI_R15_TIER_MODEL_VIOLATION` |
| 5.10 — Anonymisation/pseudonymisation | ✓ partiel | `DATA_CLASSIFICATION_MISSING` |
| 5.14 — Test périodique | ✓ info | `HDS_5_14_PENTEST_CADENCE` |
| 5.11, 5.12, 5.13 | ❌ hors scope AD | — |

### RGPD article 32

| Mesure | Détecteurs |
|---|---|
| **art.32(1)(a)** Pseudonymisation et chiffrement | `PASSWORD_REVERSIBLE_ENCRYPTION`, `ANSSI_R3_STRONG_AUTH`, `ENCRYPTION_AT_REST_DISABLED`, `DATA_CLASSIFICATION_MISSING`, `WEAK_ENCRYPTION_DES`, `WEAK_ENCRYPTION_RC4`, `NTLMV1_ALLOWED`, `LDAP_SIGNING_NOT_ENFORCED`, `HDS_5_2_TLS_NOT_ENFORCED`, `ANSSI_R9_*` |
| **art.32(1)(b)** Confidentialité, intégrité, dispo, résilience | `ANSSI_R3_STRONG_AUTH`, `ANSSI_R4_LOGGING`, `HDS_5_4_*`, `AUDIT_POLICY_INSUFFICIENT`, `NO_HONEYPOT_ACCOUNT`, `HDS_5_1_4_STRONG_AUTH` |
| **art.32(1)(c)** Restauration en cas d'incident | `BACKUP_AD_NOT_VERIFIED`, `AD_RECYCLE_BIN_DISABLED`, `NO_OFFLINE_BACKUP`, `HDS_5_8_DR_PLAN_MISSING` |
| **art.32(1)(d)** Procédure de test régulier | `HDS_5_14_PENTEST_CADENCE` |

### CIS Controls v8

Détecteurs natifs + cross-tags sur les détecteurs ANSSI/HDS qui couvrent les mêmes contrôles.

| Contrôle CIS | Détecteurs |
|---|---|
| **§1.1** Password Policy | `CIS_PASSWORD_POLICY`, `ANSSI_R1_PASSWORD_POLICY`, `WEAK_PASSWORD_POLICY`, `PASSWORD_REVERSIBLE_ENCRYPTION`, `ANSSI_R23_LM_HASH_NOT_DISABLED`, `NIST_IA_5_AUTHENTICATOR`, `DISA_ACCOUNT_POLICIES` |
| **§2.2** User Rights Assignment | `CIS_USER_RIGHTS`, `ACCOUNT_OPERATORS_MEMBER`, `SERVER_OPERATORS_MEMBER`, `PRINT_OPERATORS_MEMBER`, `BACKUP_OPERATORS_MEMBER`, `EXCESSIVE_PRIVILEGED_ACCOUNTS` |
| **§2.3** Network / Security Options | `CIS_NETWORK_SECURITY`, `LDAP_SIGNING_NOT_ENFORCED`, `SMB_SIGNING_DISABLED`, `LDAP_CHANNEL_BINDING_DISABLED`, `NTLMV1_ALLOWED` |
| **§17** Audit Policy | `ANSSI_R4_LOGGING`, `ANSSI_R38_ADVANCED_AUDIT_NOT_ENABLED`, `ANSSI_R39_SECURITY_LOG_TOO_SMALL`, `AUDIT_POLICY_INSUFFICIENT` |

### NIST SP 800-53 Rev.5

| Contrôle NIST | Détecteurs |
|---|---|
| **AC-2** Account Management | `NIST_AC_2_ACCOUNT_MANAGEMENT`, `ANSSI_R6_INACTIVE_ACCOUNTS`, `ANSSI_R7_STALE_ACCOUNTS_NOT_REMOVED`, `STALE_ACCOUNT`, `ANSSI_R2_2_GUEST_ENABLED` |
| **AC-6** Least Privilege | `NIST_AC_6_LEAST_PRIVILEGE`, `ANSSI_R2_PRIVILEGED_ACCOUNTS`, `EXCESSIVE_PRIVILEGED_ACCOUNTS`, `ANSSI_R15_TIER_MODEL_VIOLATION`, `DCSYNC_CAPABLE` |
| **IA-5** Authenticator Management | `NIST_IA_5_AUTHENTICATOR`, `ANSSI_R1_PASSWORD_POLICY`, `WEAK_PASSWORD_POLICY`, `ANSSI_R3_STRONG_AUTH`, `ANSSI_R9_SERVICE_ACCOUNT_SECRET_ROTATION` |
| **AU-2** Audit Events | `NIST_AU_2_AUDIT_EVENTS`, `ANSSI_R4_LOGGING`, `ANSSI_R38_ADVANCED_AUDIT_NOT_ENABLED`, `AUDIT_POLICY_INSUFFICIENT`, `AUDIT_LOG_RETENTION_SHORT`, `DISA_AUDIT_POLICIES` |

### DISA STIG (Windows Server / AD Domain)

| Contrôle DISA | Détecteurs |
|---|---|
| **V-73305 series** Account Policies | `DISA_ACCOUNT_POLICIES`, `ANSSI_R1_PASSWORD_POLICY`, `WEAK_PASSWORD_POLICY`, `PASSWORD_REVERSIBLE_ENCRYPTION`, `ANSSI_R23_LM_HASH_NOT_DISABLED` |
| **V-73411 series** Audit Policies | `DISA_AUDIT_POLICIES`, `ANSSI_R4_LOGGING`, `ANSSI_R38_ADVANCED_AUDIT_NOT_ENABLED`, `ANSSI_R39_SECURITY_LOG_TOO_SMALL`, `NIST_AU_2_AUDIT_EVENTS` |

