# Asset Filters — include/exclude assets & detectors

Version : v3.1.6+

Introduction à l'asset filtering pour l'auditeur AD. Permet d'exclure des OUs,
des comptes spécifiques, ou de désactiver certains détecteurs sur un périmètre
ciblé (ex : `LAPS_NOT_DEPLOYED` sur une OU où le client utilise Tenable PAM
à la place de LAPS).

## Pourquoi filtrer

Sans filtre, un audit remonte des findings sur tous les assets — y compris :

- les comptes de service legacy qu'on ne peut plus mettre à jour
- les Windows XP de test non couverts par la politique d'hygiène
- des OUs archivées (désactivées) qui gonflent artificiellement le score
- des contrôles non applicables (LAPS quand le client a déjà un autre PAM)

Le score d'audit devient non représentatif. Pour une mission client, c'est un
bloqueur.

Asset filtering permet à l'auditeur de scoper l'audit **tout en laissant
une trace signée** (`rulesHash`) dans le résultat. Le client ne peut pas
cacher ses problèmes silencieusement — le rapport montre combien d'assets
ont été exclus et par quelle règle.

## Syntaxe YAML

Fichier `exclusions.yaml` :

```yaml
version: 1

# Filtres asset-level : exclut complètement les objets
users:
  scope:                               # optionnel : restreint l'énumération
    - OU=Employees,DC=acme,DC=corp     #   à ces sous-arbres uniquement
  exclude:
    dns: ["CN=Guest,CN=Users,DC=acme,DC=corp"]
    sam_patterns: ["svc-*", "*-legacy", "*temp*"]  # glob (* et ?)
    under_ous: ["OU=Legacy,DC=acme,DC=corp"]       # subtree (inclusif)
    regex: ["^CN=backup-.*$"]                       # regex explicite

computers:
  exclude:
    dns: []
    hostname_patterns: ["*-lab", "XP-*"]            # sur dNSHostName OU sAMAccountName
    under_ous: ["OU=Obsolete,DC=acme,DC=corp"]

groups:
  exclude:
    dns: []
    name_patterns: []                                # sur CN ou sAMAccountName

ous:
  exclude:
    dns: ["OU=Archive,DC=acme,DC=corp"]

# Filtres detector-level : l'asset reste scanné mais ce détecteur ne s'y applique pas
detectors:
  - id: LAPS_NOT_DEPLOYED
    reason: "Tenable PAM gère l'accès privilégié — LAPS volontairement non déployé"
    scope:
      computers:
        under_ous: ["OU=Tenable-Managed,DC=acme,DC=corp"]
  - id: WEAK_PASSWORD_POLICY
    reason: "Apps legacy nécessitent MD5 — documenté au risk registry"
    scope:
      users:
        sam_patterns: ["svclegacy-*"]
```

### Champs par type d'asset

| Type | Pattern sur | Champ |
|---|---|---|
| `users` | `sAMAccountName` | `sam_patterns` |
| `computers` | `dNSHostName` puis fallback `sAMAccountName` sans `$` | `hostname_patterns` |
| `groups` | `CN` puis `sAMAccountName` | `name_patterns` |
| `ous` | `name` (RDN) | `name_patterns` |
| tous | `DN` exact | `dns` |
| tous | sous-arbre | `under_ous` |
| tous | regex sur DN | `regex` |

### Sémantique glob

Seuls `*` (zéro ou plusieurs caractères) et `?` (un caractère) sont spéciaux.
Tous les autres caractères sont littéraux. Comparaison **insensible à la
casse**.

- `svc-*` matche `svc-sql`, `SVC-BACKUP`
- `*-legacy` matche `app-legacy`, `CRM-LEGACY`
- `XP-?` matche `XP-1`, `xp-a` mais **pas** `XP-12`

### Normalisation des DN

Les DNs sont normalisés avant comparaison : lowercase + suppression des
espaces autour de `=` et `,`. Donc `CN = Foo , OU = Bar` matche
`cn=foo,ou=bar`.

## Utilisation

### CLI (mode standalone server)

```bash
# 1. Découverte des assets (pour construire exclusions.yaml)
etc-collector discover ad \
  --ldap-url ldap://dc:389 \
  --ldap-bind-dn "CN=Admin,CN=Users,DC=acme,DC=corp" \
  --ldap-bind-password "..." \
  --ldap-base-dn "DC=acme,DC=corp" \
  -o assets.json

# 2. Audit avec filtres (dry-run : prévisualisation sans modifier)
etc-collector audit ad \
  --ldap-url ldap://dc:389 \
  --ldap-bind-dn "CN=Admin,CN=Users,DC=acme,DC=corp" \
  --ldap-bind-password "..." \
  --ldap-base-dn "DC=acme,DC=corp" \
  --exclusions ./exclusions.yaml \
  --exclusions-dry-run \
  -o audit-dry.json

# 3. Audit avec filtres (réel)
etc-collector audit ad ... --exclusions ./exclusions.yaml -o audit.json
```

### Inline dans `collector.yaml`

Alternative pour configs simples : inclure `assetFilters:` sous la section
`audit:` dans `collector.yaml` :

```yaml
audit:
  scope:
    profile: ""
  assetFilters:
    version: 1
    users:
      exclude:
        sam_patterns: ["svc-*"]
```

Le flag `--exclusions` a priorité sur `assetFilters:` inline.

### Depuis le SaaS

Deux nouvelles commandes poussées par le backend :

- `DISCOVER_AD` — déclenche une énumération, retourne un manifest (counts +
  OU tree + samples).
- `UPDATE_ASSET_FILTERS_AD` — push d'une config `assetFilters`. Validée au
  chargement (regex compile, DN non-vides), persistée dans
  `credentials.json`, appliquée aux audits suivants.

Paramètres de commande :

```json
{
  "commandId": "...",
  "type": "UPDATE_ASSET_FILTERS_AD",
  "parameters": {
    "assetFilters": { /* même format que exclusions.yaml mais en JSON */ }
  }
}
```

Envoyer `{"assetFilters": {}}` vide la config.

Le résultat d'audit remonté au SaaS contient les counts + rulesHash dans
`audit.summary.exclusions` (voir section "Trail" plus bas).

## Le rulesHash (trail d'audit)

Chaque résultat d'audit embarque :

```json
{
  "audit": {
    "summary": {
      "objects": { "users": 545, "computers": 74, ... },
      "risk": { "score": 33.1, "rating": "high" },
      "exclusions": {
        "rulesHash": "6e222bf3ee9b526c1256216fb32ad87b6d2a9608f6e4199b398b0a491a2644d3",
        "rulesVersion": 1,
        "assetCounts": {
          "users":     { "total": 546, "scanned": 545, "excluded": 1, "reasons": [...] },
          "computers": { "total": 74, "scanned": 74, "excluded": 0 },
          "groups":    { "total": 154, "scanned": 154, "excluded": 0 },
          "ous":       { "total": 352, "scanned": 352, "excluded": 0 }
        },
        "perDetector": [
          {
            "detectorId": "LAPS_NOT_DEPLOYED",
            "reason": "Tenable PAM gère l'accès privilégié",
            "scope": "computers",
            "matched": 69,
            "sampleDNs": ["CN=..."]
          }
        ]
      }
    }
  }
}
```

`rulesHash` = SHA256 de la config normalisée. Un auditeur externe peut
comparer deux audits successifs :

- **hash identique** → même config filtre → comparaison score directe.
- **hash différent** → la config a bougé, évaluer l'impact avant de
  comparer les scores.

Un warning est ajouté à `audit.warnings` si une catégorie excède 10 %
d'exclusions :

```json
{
  "code": "ASSET_FILTER_SIGNIFICANT",
  "message": "Score based on filtered asset set — significant exclusions applied (rulesHash=...)"
}
```

## Validation

- Regex invalide → l'audit refuse de démarrer avec l'erreur ligne/champ.
- `dns` vide, `version` absent ou différent de 1 → idem.
- Pour tester avant commit : `--exclusions-dry-run` applique la logique
  sans modifier les données, permet de valider l'impact.

## Exemples typiques

### Exclure les comptes de service

```yaml
version: 1
users:
  exclude:
    sam_patterns: ["svc-*", "srv-*", "_svc*"]
```

### Exclure OU legacy

```yaml
version: 1
users:
  exclude:
    under_ous: ["OU=Legacy,DC=acme,DC=corp"]
computers:
  exclude:
    under_ous: ["OU=Legacy,DC=acme,DC=corp"]
ous:
  exclude:
    dns: ["OU=Legacy,DC=acme,DC=corp"]
```

### LAPS non applicable sur périmètre managé

```yaml
version: 1
detectors:
  - id: LAPS_NOT_DEPLOYED
    reason: "CyberArk PAM gère l'accès privilégié (documenté au risk registry)"
    scope:
      computers:
        under_ous: ["OU=CyberArk-Managed,DC=acme,DC=corp"]
```

Les machines sous cette OU apparaissent toujours dans les findings LAPS
d'autres types (ex : `LAPS_PASSWORD_READABLE_BY_NON_ADMINS`), mais pas dans
`LAPS_NOT_DEPLOYED`.
