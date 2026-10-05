# Azure / Entra ID - démarrage rapide (admin junior)

Ce document est le **premier fichier à lire** pour configurer la connexion Azure/Entra ID du collecteur. Public cible : admin Entra sans expérience préalable d'audit tooling. À la fin vous aurez un fichier JSON d'audit en moins de 15 minutes.

> Pour la liste complète des permissions Graph et le détail de l'authentification par certificat, voir [permissions.md#azure-entra-id](permissions.md#azure-entra-id).
> Pour les variables d'environnement `AZURE_*`, voir [environment-variables.md](environment-variables.md).
> Pour la config `azure:` complète dans `config.yaml`, voir [README.md](README.md).

---

## 1. Trois questions à se poser avant tout

| # | Question | Réponse OUI | Réponse NON |
|---|---|---|---|
| Q1 | Êtes-vous **Global Administrator** (ou pouvez-vous demander l'admin consent à quelqu'un qui l'est) ? | Vous pouvez accorder les permissions Graph vous-même (§4) | Préparez la table du §4 pour votre Global Admin |
| Q2 | Votre tenant **interdit-il la création de client secrets** (courant en secteur public/régulé) ? | Utilisez un **certificat client** (§3bis) | Un **client secret** suffit (§3) - plus simple |
| Q3 | Avez-vous une licence **Entra ID P2** ? | Le détecteur "risky users" fonctionnera pleinement | La permission `IdentityRiskyUser.Read.All` échouera avec `403` même consentie - c'est normal, pas une erreur de config (voir §4) |

---

## 2. Créer l'App Registration

### 2.1 Via le portail Azure

1. **Entra ID → App registrations → New registration**
2. Nom : `ETC Collector` (ou autre nom reconnaissable)
3. Supported account types : **Accounts in this organizational directory only** (single tenant)
4. Redirect URI : laisser vide - le collecteur utilise le flux **client credentials** (app-only), pas de redirection interactive
5. **Register**

### 2.2 Via Azure CLI (équivalent scriptable)

```bash
az login

APP_NAME="ETC Collector"
az ad app create --display-name "$APP_NAME"

# Récupère l'App (Client) ID
APP_ID=$(az ad app list --display-name "$APP_NAME" --query "[0].appId" -o tsv)
echo "App ID: $APP_ID"

# Crée le service principal associé - obligatoire, sans lui le client credentials
# flow échoue même si l'app registration existe
az ad sp create --id "$APP_ID"
```

---

## 3. Récupérer Tenant ID + Client ID, et créer un secret

```bash
# Tenant ID
az account show --query tenantId -o tsv

# Client (Application) ID - déjà récupéré au §2.2, ou depuis le portail :
# App registrations → votre app → Overview → "Application (client) ID"
```

### 3.1 Client secret (cas standard)

```bash
# Valide 2 ans - az affiche le secret UNE SEULE FOIS
SECRET=$(az ad app credential reset --id "$APP_ID" --years 2 --query password -o tsv)
echo "Client Secret: $SECRET"
```

Portail : **App registrations → votre app → Certificates & secrets → Client secrets → New client secret**.

> Un secret expire (ici en 2 ans). Notez la date dans votre calendrier - un secret expiré casse l'audit sans avertissement préalable côté Azure.

### 3bis. Certificat client (tenants qui interdisent les secrets)

Le collecteur accepte un secret **ou** un certificat (`--client-secret` vs `--client-cert`) - l'un des deux est obligatoire, et si les deux sont configurés en même temps, le certificat gagne. Vérifié dans `internal/providers/azure/client.go` : `NewClient` refuse la création si ni l'un ni l'autre n'est fourni.

```bash
# Génère une paire clé/certificat auto-signée, 2 ans, RSA 2048
openssl req -x509 -newkey rsa:2048 -sha256 -days 730 -nodes \
  -keyout entra-key.pem -out entra-cert.pem \
  -subj "/CN=ETC Collector"

# Le collecteur a besoin des DEUX parties dans un seul fichier
cat entra-cert.pem entra-key.pem > entra.pem
chmod 600 entra.pem

# Upload de la partie PUBLIQUE uniquement sur l'app registration
az ad app credential reset --id "$APP_ID" --cert "@entra-cert.pem" --append
```

La procédure complète (PKCS#12/.pfx, rotation, pièges OpenSSL 3 avec `-legacy`) est documentée dans [permissions.md § Certificate Authentication](permissions.md#certificate-authentication-recommended) - ne la dupliquons pas ici.

---

## 4. Permissions Microsoft Graph requises (Application, app-only) + admin consent

Le collecteur teste **13 permissions Graph** avant chaque audit (`requiredPermissions`, `internal/providers/azure/client.go`). Toutes sont de type **Application** (app-only, pas déléguées) - accordez-les exactement comme listé, le type compte :

| Permission Graph | Utilisée pour |
|---|---|
| `Directory.Read.All` | Lecture générale de l'annuaire (utilisateurs, groupes, infos de domaine, organisation) |
| `User.Read.All` | Profils utilisateurs complets |
| `Group.Read.All` | Groupes, membres, propriétaires |
| `Application.Read.All` | App registrations et service principals (détection de sur-permissionnement OAuth) |
| `RoleManagement.Read.All` | Attributions de rôles permanentes **et** éligibles PIM |
| `RoleManagementPolicy.Read.Directory` | Politiques PIM (règles d'activation, MFA requise, durée max) |
| `Policy.Read.All` | Conditional Access, Named Locations, politiques d'authentification, Security Defaults |
| `AuditLog.Read.All` | Logs de connexion (sign-ins) et logs d'audit d'annuaire |
| `DelegatedPermissionGrant.Read.All` | Consentements OAuth délégués existants (détection de consentements risqués) |
| `CrossTenantInformation.ReadBasic.All` | Politiques cross-tenant B2B (partenaires, organisation multi-tenant) |
| `IdentityRiskyUser.Read.All` | Utilisateurs à risque (Identity Protection) - **nécessite Entra ID P2**, voir Q3 au §1 |
| `Organization.Read.All` | Informations de licence (SKUs), déclaration de confidentialité du tenant |
| `UserAuthenticationMethod.Read.All` | Enregistrement MFA par utilisateur, rapport de couverture MFA |

### 4.1 Via le portail

**App registrations → votre app → API permissions → Add a permission → Microsoft Graph → Application permissions**, cochez les 13 permissions ci-dessus, puis **Grant admin consent for `<tenant>`** (bouton visible seulement si vous êtes Global Admin).

### 4.2 Via Azure CLI (boucle sur les 13 permissions)

Les IDs de permission (GUID) sont propres à chaque type (Application vs Delegated) et ne sont pas mnémotechniques - plutôt que de les recopier à la main (risque de coller le mauvais GUID sur le mauvais tenant), on les résout dynamiquement depuis le service principal Microsoft Graph lui-même :

```bash
GRAPH_ID="00000003-0000-0000-c000-000000000000"   # App ID de Microsoft Graph - constant, identique sur tous les tenants

PERMISSIONS=(
  Directory.Read.All
  User.Read.All
  Group.Read.All
  Application.Read.All
  RoleManagement.Read.All
  RoleManagementPolicy.Read.Directory
  Policy.Read.All
  AuditLog.Read.All
  DelegatedPermissionGrant.Read.All
  CrossTenantInformation.ReadBasic.All
  IdentityRiskyUser.Read.All
  Organization.Read.All
  UserAuthenticationMethod.Read.All
)

for PERM_NAME in "${PERMISSIONS[@]}"; do
  # Cherche le rôle "Application" (appRoles, pas oauth2PermissionScopes qui sont
  # les permissions déléguées) portant ce nom exact sur le SP Microsoft Graph.
  PERM_ID=$(az ad sp show --id "$GRAPH_ID" \
    --query "appRoles[?value=='$PERM_NAME'].id" -o tsv)
  if [ -z "$PERM_ID" ]; then
    echo "ERREUR: permission Application '$PERM_NAME' introuvable sur le SP Graph" >&2
    continue
  fi
  az ad app permission add --id "$APP_ID" --api "$GRAPH_ID" --api-permissions "${PERM_ID}=Role"
  echo "Added: $PERM_NAME"
done

# Admin consent - obligatoire pour des permissions Application, doit être fait
# par un Global Administrator
az ad app permission admin-consent --id "$APP_ID"
echo "Admin consent granted."
```

> **Admin consent est obligatoire.** Sans lui, chaque appel Graph répond `403 Forbidden` même si la permission apparaît "Added" dans la liste - l'ajout et le consentement sont deux étapes distinctes.

---

## 5. Lancer l'audit

```bash
etc-collector audit azure \
  --tenant-id "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" \
  --client-id "yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy" \
  --client-secret "$SECRET" \
  -o /tmp/audit-azure.json
```

Ou avec un certificat client :

```bash
etc-collector audit azure \
  --tenant-id "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" \
  --client-id "yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy" \
  --client-cert /etc/etc-collector/entra.pem \
  -o /tmp/audit-azure.json
```

### Vérification automatique des permissions avant l'audit

Avant de lancer les détecteurs, le collecteur teste chacune des 13 permissions du §4 avec un appel Graph léger (`$top=1`) et journalise le résultat :

```
INFO  Checking Azure permissions...
WARN  Permission missing  permission=IdentityRiskyUser.Read.All error="403 Forbidden"
WARN  Some permissions are missing. Detectors that depend on them will not produce results.  granted=12 missing=1 total=13
```

**L'audit continue même si des permissions manquent** - seuls les détecteurs qui dépendent de la permission absente ne produisent pas de résultat, le reste tourne normalement. Pour désactiver cette vérification préalable (par exemple si vous savez déjà que tout est en place et voulez gagner quelques secondes) : `--skip-permission-check`.

> Il n'existe pas de commande dédiée « tester les permissions Azure sans auditer » - contrairement à `discover ad` côté Active Directory. Lancer `audit azure` normalement est la façon de vérifier votre configuration ; le rapport JSON contient les résultats même en cas de permissions partielles.

Si succès : fichier JSON dans `/tmp/audit-azure.json`, même structure `audit.summary.risk.{score,findings}` et `audit.summary.complianceScores[]` que pour un audit AD - voir [ad-getting-started.md](ad-getting-started.md) pour un exemple de lecture avec `jq`, ou [API.md](../API.md) pour le schéma JSON complet.

---

## 6. Précédence de configuration

Comme pour tout le reste du collecteur : **CLI flag > variable d'environnement `AZURE_*` > `config.yaml` > défaut**. Trois façons équivalentes de fournir les mêmes identifiants :

```bash
# 1. Flags CLI (vus au §5)
etc-collector audit azure --tenant-id "..." --client-id "..." --client-secret "..."

# 2. Variables d'environnement
export AZURE_TENANT_ID="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
export AZURE_CLIENT_ID="yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy"
export AZURE_CLIENT_SECRET="your-secret"
etc-collector audit azure

# 3. config.yaml (mode server/daemon)
```
```yaml
azure:
  tenantId: "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
  clientId: "yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy"
  clientSecret: "${AZURE_CLIENT_SECRET}"
```

Détail complet des variables `AZURE_*` (y compris `AZURE_CLIENT_CERT_PEM`, sans équivalent CLI) : [environment-variables.md](environment-variables.md).

---

## 7. Si ça plante

| Symptôme | Cause | Fix express |
|---|---|---|
| `create Azure client: tenant ID is required` | `--tenant-id` absent des trois sources (§6) | Vérifiez CLI/env/config.yaml |
| `a client secret or a client certificate is required` | Ni `--client-secret` ni `--client-cert` fourni | Fournissez l'un des deux (§3 / §3bis) |
| Permission `403 Forbidden` sur toutes les permissions | Admin consent jamais accordé | `az ad app permission admin-consent --id "$APP_ID"` (§4) |
| Permission `403` uniquement sur `IdentityRiskyUser.Read.All` | Licence Entra ID P2 absente (probable) ou consent manquant | Normal sans P2 (voir Q3 au §1) - pas un bug de configuration |
| `parse client certificate ... unknown digest algorithm` | PKCS#12 exporté par OpenSSL 3 (AES-256-CBC), non lisible par le SDK Azure | `openssl pkcs12 -export -legacy ...`, ou convertir en PEM - détail dans [permissions.md](permissions.md#certificate-authentication-recommended) |
| Le fichier `--client-cert` contient un certificat mais pas de clé privée | Vous avez uploadé la partie publique (`entra-cert.pem`) au lieu du bundle complet | Pointez `--client-cert` vers le fichier concaténé (§3bis), gardez `entra-cert.pem` uniquement pour l'upload Entra |

Pour la table complète des permissions et l'authentification par certificat en détail, voir [permissions.md#azure-entra-id](permissions.md#azure-entra-id).
