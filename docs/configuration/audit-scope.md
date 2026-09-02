# Audit scope — choisir quels détecteurs exécuter

À partir de **v3.0.22**, vous pouvez restreindre un audit à un sous-ensemble de détecteurs via 3 axes combinables :

1. **Catégories** — granularité moyenne (ex: `kerberos`, `adcs`, `permissions`)
2. **IDs de détecteur** — précis (ex: `AD_KERBEROS_AS_REP_ROASTING`)
3. **Profils nommés** — presets (`quick`, `compliance`, `pentest`)

Disponible en CLI, env vars, YAML et payload SaaS — surfaces unifiées.

> Pour découvrir la liste exhaustive des catégories / IDs / profils : `etc-collector audit list`

---

## Précédence

```
final_set = (profile_categories ∪ include_categories) ∪ include_detectors
final_set −= exclude_categories
final_set −= exclude_detectors
```

- Sans rien spécifié : **tous les détecteurs** (507 au 2026-09-02, `etc-collector audit list` — un seul binaire depuis v3.2.0, plus de split Community/Pro).
- `exclude` gagne toujours sur `include` (sémantique firewall).
- Un `--scope-profile` inconnu ou une catégorie inconnue produit un **warning** sans bloquer l'audit (fallback = tous les détecteurs).

---

## Profils disponibles

| Profil | Catégories incluses | Cas d'usage |
|---|---|---|
| `quick` | accounts, kerberos, password, computers | spot-check rapide < 5s |
| `compliance` | compliance, azureCompliance | audit CIS/NIST/ANSSI/DISA uniquement |
| `pentest` | kerberos, permissions, adcs, attack-paths, advanced | red-team / surface offensive |

Liste mise à jour à chaque release ; la commande `etc-collector audit list` affiche la composition exacte.

---

## CLI

5 flags disponibles sur **`audit ad`**, **`audit azure`** et toutes les autres sous-commandes audit :

```bash
etc-collector audit ad \
  --ldap-url ldaps://dc01.example.com:636 \
  --ldap-bind-dn "..." --ldap-bind-password "..." --ldap-base-dn "..." \
  --scope-profile quick \
  --scope-include-categories adcs \
  --scope-exclude-detectors AD_GPO_LLMNR_ENABLED \
  -o audit.json
```

### Tous les flags

| Flag | Type | Env var |
|---|---|---|
| `--scope-profile` | string | `AUDIT_PROFILE` |
| `--scope-include-categories` | comma-separated | `AUDIT_INCLUDE_CATEGORIES` |
| `--scope-exclude-categories` | comma-separated | `AUDIT_EXCLUDE_CATEGORIES` |
| `--scope-include-detectors` | comma-separated | `AUDIT_INCLUDE_DETECTORS` |
| `--scope-exclude-detectors` | comma-separated | `AUDIT_EXCLUDE_DETECTORS` |

Précédence : flag CLI > env var > YAML config.

### Exemples

```bash
# Profil quick uniquement
etc-collector audit ad ... --scope-profile quick

# Tout sauf network et monitoring
etc-collector audit ad ... --scope-exclude-categories network,monitoring

# Seulement kerberos, mais pas le détecteur AS-REP roasting
etc-collector audit ad ... \
  --scope-include-categories kerberos \
  --scope-exclude-detectors AD_KERBEROS_AS_REP_ROASTING

# Profil pentest étendu avec ADCS et compliance
etc-collector audit ad ... \
  --scope-profile pentest \
  --scope-include-categories adcs,compliance

# Découverte
etc-collector audit list
```

---

## YAML (mode `server`)

```yaml
audit:
  scope:
    profile: ""                  # quick | compliance | pentest | ""
    includeCategories: []        # ex: [kerberos, permissions]
    excludeCategories: []        # ex: [network, monitoring]
    includeDetectors: []         # ex: [AD_KERBEROS_AS_REP_ROASTING]
    excludeDetectors: []         # ex: [AD_GPO_LLMNR_ENABLED]
```

Le mode `server` consomme cette config pour les audits déclenchés via API REST. Les flags CLI `audit ad` peuvent override en mode one-shot.

---

## SaaS daemon — payload `params.scope`

Le backend SaaS pousse le scope dans le payload de `RUN_AUDIT_AD` ou `RUN_AUDIT_AZURE` :

```json
{
  "id": "uuid",
  "type": "RUN_AUDIT_AD",
  "params": {
    "includeDetails": true,
    "scope": {
      "profile": "quick",
      "includeCategories": ["adcs"],
      "excludeCategories": ["network"],
      "includeDetectors": [],
      "excludeDetectors": ["AD_GPO_LLMNR_ENABLED"]
    }
  }
}
```

Tous les champs sont optionnels. `params.scope` absent ou `null` = tous les détecteurs (comportement v3.0.21).

Le résultat retourné inclut les éventuels warnings :

```json
{
  "status": "success",
  "result": {
    "warnings": [
      { "type": "scope", "message": "unknown detector ID \"AD_NOT_REAL\"" }
    ],
    "audit": { ... }
  }
}
```

(Les warnings de scope sont aussi loggés côté daemon : `WARN scope warning ...`)

---

## Mode `trial`

Identique au SaaS daemon : `params.scope` dans la commande `RUN_AUDIT_*`. Tous les champs optionnels.

---

## Comment découvrir ce qu'on peut mettre

```bash
$ etc-collector audit list
PROFILES
  compliance   compliance, azureCompliance
  pentest      kerberos, permissions, adcs, attack-paths, advanced
  quick        accounts, kerberos, password, computers

CATEGORIES (count = registered detectors)
  accounts                34
  adcs                    11
  advanced                50
  applications            28
  ...

DETECTORS (id, category)
  AD_GPO_LLMNR_ENABLED                               gpo
  AD_KERBEROS_AS_REP_ROASTING                        kerberos
  ...

Total: 507 detectors across 22 categories, 3 profiles
```

Sortie complète : ~507 lignes. Pipe vers `grep` pour filtrer (ex: `audit list | grep kerberos`).

---

## Comportement sur valeur inconnue

| Cas | Comportement |
|---|---|
| `--scope-profile nope` | Warning logué, base = tous les détecteurs |
| `--scope-include-categories nope,kerberos` | Warning sur `nope`, kerberos appliqué |
| `--scope-include-detectors NO_SUCH_ID` | Warning logué, ID ignoré |
| `--scope-exclude-detectors NO_SUCH_ID` | Warning logué, exclusion sans effet |

Pas de fail strict : un audit avec scope mal orthographié tournera quand même (fallback sur le default ou le subset reconnu).

---

## Cas d'usage typiques

### "Audit rapide kerberos sur ce DC"
```bash
etc-collector audit ad ... --scope-include-categories kerberos
```

### "Enlever les checks réseau bruyants en SaaS prod"
SaaS payload :
```json
{ "scope": { "excludeCategories": ["network"] } }
```

### "Auditer uniquement la compliance pour un client RGPD"
```bash
etc-collector audit ad ... --scope-profile compliance
```

### "Profil pentest mais sans LLMNR (déjà tracké côté Wazuh)"
```bash
etc-collector audit ad ... \
  --scope-profile pentest \
  --scope-exclude-detectors AD_GPO_LLMNR_ENABLED
```

### "Mode 'paranoia max' = tous les détecteurs y compris ADCS Pro"
```bash
etc-collector audit ad ...    # scope vide = tous
```
