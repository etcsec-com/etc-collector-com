# Active Directory — modes de connexion

ETC Collector se connecte à Active Directory via **LDAP**, **LDAPS** ou **LDAP + StartTLS**. Ce document explique les 3 modes, quand utiliser chacun, et les options TLS disponibles.

> 🆕 **Nouveau ?** Commencez par [ad-getting-started.md](ad-getting-started.md) — guide pas-à-pas pour admin junior avec arbre de décision et 5 walkthroughs.
> Pour les erreurs de connexion, voir [ad-troubleshooting.md](ad-troubleshooting.md).
> Pour extraire et installer les certificats CA, voir [ad-tls-certificates.md](ad-tls-certificates.md).

---

## Vue d'ensemble

| Mode | Port | URL scheme | Confidentialité | Quand l'utiliser |
|---|---|---|---|---|
| **LDAPS** *(recommandé)* | 636 | `ldaps://` | TLS direct | Production. La plupart des DC modernes l'ont activé par défaut |
| **LDAP + StartTLS** | 389 | `ldap://` + flag `startTLS: true` | TLS upgrade post-connect | Le DC n'écoute que sur 389 mais supporte StartTLS (rare en AD natif) |
| **LDAP plain** | 389 | `ldap://` | **Aucune** (cleartext) | Lab uniquement, ou si LDAP signing n'est pas enforced ET que la confidentialité ne compte pas |

**Décision rapide** :
- DC moderne (Windows Server 2012+) avec AD CS → **LDAPS**, c'est l'option normale.
- LDAPS bloqué/non activé mais le DC accepte StartTLS → **StartTLS**.
- Tout le reste casse → **LDAP plain** en dernier recours (et seulement si le DC autorise les binds non-signés).

---

## Options TLS exposées (v3.0.21+)

À partir de **v3.0.21**, toutes les options TLS sont disponibles partout — CLI, env, YAML server, SaaS daemon, API admin et mode trial :

| Option | CLI flag | Env var | YAML field |
|---|---|---|---|
| Vérifier le cert serveur | `--ldap-tls-verify` | `LDAP_TLS_VERIFY` | `tlsVerify` |
| CA personnalisée (chemin fichier) | `--ldap-ca-cert` | `LDAP_TLS_CA_CERT` | `tlsCACert` |
| CA personnalisée (PEM inline) | — *(pas pratique en CLI)* | `LDAP_TLS_CA_CERT_PEM` | `tlsCACertPEM` |
| StartTLS sur ldap://389 | `--ldap-start-tls` | `LDAP_START_TLS` | `startTLS` |
| Version TLS minimum | `--ldap-tls-min-version` | `LDAP_TLS_MIN_VERSION` | `tlsMinVersion` |

**Priorité** : flag CLI > env var > YAML > défaut.

**Cas d'usage** : si la CA du DC n'est pas dans le truststore système de la machine collecteur, vous avez 3 options :

1. **Installer la CA dans le truststore système** (zéro option à configurer ensuite, voir [ad-tls-certificates.md](ad-tls-certificates.md))
2. **Pointer `--ldap-ca-cert` vers un fichier PEM** (option la plus simple en one-shot)
3. **Désactiver la vérification** avec `--ldap-tls-verify=false` (acceptable en lab, **pas** en prod)

---

## Mode 1 — LDAPS (recommandé)

### Configuration CLI

```bash
etc-collector audit ad \
  --ldap-url ldaps://dc01.example.com:636 \
  --ldap-bind-dn "CN=svc-audit,CN=Users,DC=example,DC=com" \
  --ldap-bind-password '••••' \
  --ldap-base-dn "DC=example,DC=com" \
  -o audit.json
```

Par défaut, `--ldap-tls-verify=true`. Le binaire vérifie la chaîne X.509 contre le truststore système.

### Configuration YAML (mode `server`)

```yaml
ldap:
  url: "ldaps://dc01.example.com:636"
  bindDN: "CN=svc-audit,CN=Users,DC=example,DC=com"
  bindPassword: "${LDAP_BIND_PASSWORD}"
  baseDN: "DC=example,DC=com"
  tlsVerify: true
  timeout: 30s
```

### Trace d'exécution réussie (exemple — forme réelle du log)

```
21:54:01  INFO  Starting Active Directory audit  ldap_url=ldaps://dc01.example.com:636 base_dn=DC=example,DC=cc
21:54:02  INFO  Audit completed  findings=270 score=33 rating=high duration=1.08s
21:54:02  INFO  Results written  file=/tmp/audit.json size=3182347
```

Ce mode a été rejoué contre un vrai DC le 2026-09-02 (v3.2.0) — même forme
de sortie, chiffres différents (dépendent du contenu de l'AD testé). Voir
[ad-getting-started.md, Annexe B, scénarios 1/3/4](ad-getting-started.md#annexe-b--tests-réels-effectués-v320).

10 frameworks compliance scorés dans le JSON : `ANSSI_PA099`, `ANSSI_BP039`, `ANSSI_GUIDE_HYGIENE`, `HDS_v1_1`, `RGPD`, `NIS2_FR`, `CIS_v8`, `NIST_800_53`, `DISA_STIG`.

### Cas limite : DC n'écoute pas sur 636

Vérifiez côté DC :

```powershell
Get-NetTCPConnection -State Listen | Where-Object { $_.LocalPort -in 389,636,3268,3269 }
```

Si `:636` absent, le DC n'a pas de certificat Schannel valide. Voir [ad-tls-certificates.md#dc-sans-cert](ad-tls-certificates.md#cas-particulier--dc-sans-certificat-ldaps).

---

## Mode 2 — LDAP + StartTLS

Le client se connecte en clair sur 389 puis émet la commande `StartTLS` LDAP pour upgrader la connexion. Le contenu (bind, recherches) circule chiffré.

### Configuration

#### CLI

```bash
etc-collector audit ad \
  --ldap-url ldap://dc01.example.com:389 \
  --ldap-start-tls \
  --ldap-ca-cert /path/to/ca.pem \
  --ldap-bind-dn "CN=svc-audit,CN=Users,DC=example,DC=com" \
  --ldap-bind-password '••••' \
  --ldap-base-dn "DC=example,DC=com" \
  -o audit.json
```

#### YAML

```yaml
ldap:
  url: "ldap://dc01.example.com:389"   # scheme ldap:// + port 389
  startTLS: true                        # active l'upgrade
  tlsVerify: true
  tlsCACert: "/path/to/ca.pem"
  bindDN: "CN=svc-audit,CN=Users,DC=example,DC=com"
  bindPassword: "${LDAP_BIND_PASSWORD}"
  baseDN: "DC=example,DC=com"
```

### Quand l'utiliser

- DC hardcodé sur 389 (config legacy / firewall qui ne route pas 636)
- Compatibilité avec un proxy LDAP qui n'écoute pas sur 636

En AD natif récent, **LDAPS direct est plus simple**.

---

## Mode 3 — LDAP plain (cleartext)

```bash
etc-collector audit ad \
  --ldap-url ldap://dc01.example.com:389 \
  ...
```

### Trace d'exécution réussie

```
14:11:59  INFO  Starting Active Directory audit  ldap_url=ldap://dc01.example.com:389 ...
14:11:59  INFO  Connecting to LDAP...
14:11:59  INFO  LDAP connected
14:11:59  INFO  SMB/SYSVOL connected
```

### Avertissement

Tous les binds (donc le mot de passe du compte de service) circulent **en clair** sur le réseau. À éviter sauf si :
- Le DC enforce LDAP signing (`LDAPServerIntegrity=2` dans `HKLM\SYSTEM\CCS\Services\NTDS\Parameters`) → dans ce cas le bind plain échoue avec `LDAP Result Code 8 "Strong Auth Required"` (voir [troubleshooting](ad-troubleshooting.md#erreur--ldap-result-code-8-strong-auth-required))
- C'est un environnement isolé (lab, test)

### Comment vérifier la politique LDAP signing du DC

```powershell
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" |
  Select LDAPServerIntegrity
```

| Valeur | Comportement |
|---|---|
| `1` (défaut) | Negotiate — bind plain accepté |
| `2` | Required — bind plain refusé, signing/sealing obligatoire (LDAPS ou Kerberos) |

---

## Pré-requis réseau

| Source | Destination | Port | Protocole | Pourquoi |
|---|---|---|---|---|
| Collecteur | DC | **636** | TCP | LDAPS |
| Collecteur | DC | **389** | TCP | LDAP plain / StartTLS |
| Collecteur | DC | **445** | TCP | SMB pour SYSVOL/GPO |
| Collecteur | DNS | **53** | UDP/TCP | Résolution du FQDN du DC |
| Collecteur | AD CS (si présent) | **80** | TCP | Probe ESC8 (optionnel, `--enable-network-probes`) |

Le collecteur fait **uniquement de la lecture** ; aucun port en écoute n'est requis sur le DC.

---

## Pré-requis DNS

Le `--ldap-url` doit utiliser un FQDN qui :
1. Résout vers l'IP du DC
2. **Correspond au SAN du certificat** présenté par le DC

Test rapide :

```bash
# Linux/macOS
openssl s_client -connect dc01.example.com:636 -showcerts < /dev/null 2>&1 | grep -E "subject|DNS:"

# Windows (PowerShell)
[Net.HttpWebRequest]::Create("https://dc01.example.com:636").GetResponse() 2>$null
# Ou voir les SAN :
$cert = (Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Subject -like "*dc01*" })[0]
$cert.Extensions | Where-Object { $_.Oid.FriendlyName -like "*Subject Alternative Name*" } |
  ForEach-Object { $_.Format($true) }
```

Si l'IP est utilisée à la place du FQDN (`ldaps://10.0.0.10:636`), la vérification échoue avec le code `LDAP_TLS_IP_SAN_MISSING`. Rejoué contre un vrai DC le 2026-09-02 (v3.2.0, [Annexe B scénario 2](ad-getting-started.md#annexe-b--tests-réels-effectués-v320)) :

```
Error: LDAP connection failed:
[LDAP_TLS_IP_SAN_MISSING] LDAP URL uses an IP address but the certificate has no IP SAN
  → Fix:  Use the DC FQDN listed in the certificate SAN (run: openssl s_client -connect HOST:636 -showcerts).
  → Raw:  LDAP Result Code 200 "Network Error": tls: failed to verify certificate: x509: cannot validate certificate for 10.0.0.10 because it doesn't contain any IP SANs
```

**Workaround sans DNS interne** : ajouter une entrée `/etc/hosts` (Linux) ou `C:\Windows\System32\drivers\etc\hosts` (Windows) qui mappe le FQDN vers l'IP. Voir [ad-troubleshooting.md](ad-troubleshooting.md#erreur--x509-cannot-validate-certificate-for-xxx-because-it-doesnt-contain-any-ip-sans).

---

## Compte de service AD requis

Le compte utilisé pour le bind doit avoir :

- Membre de **Domain Users** (lecture standard suffisante)
- Lecture sur `nTSecurityDescriptor` (héritée de Domain Users par défaut)
- Aucun droit d'écriture nécessaire (le collecteur est strictement lecture)

Voir [permissions.md](permissions.md#active-directory) pour la création détaillée d'un compte de service dédié.

---

## Tester votre configuration en 30 secondes

```bash
# 1. La résolution DNS marche
nslookup dc01.example.com

# 2. Le port 636 est ouvert
nc -zv dc01.example.com 636
# ou : Test-NetConnection dc01.example.com -Port 636

# 3. Le cert présenté est valide pour ce nom
openssl s_client -connect dc01.example.com:636 -servername dc01.example.com < /dev/null 2>&1 | grep -E "subject=|Verification"

# 4. Le collecteur arrive à se connecter
etc-collector audit ad \
  --ldap-url ldaps://dc01.example.com:636 \
  --ldap-bind-dn "CN=svc-audit,CN=Users,DC=example,DC=com" \
  --ldap-bind-password "$LDAP_PASS" \
  --ldap-base-dn "DC=example,DC=com" \
  -o /tmp/test.json
```

Si l'étape 4 échoue, comparer avec le tableau d'erreurs de [ad-troubleshooting.md](ad-troubleshooting.md).
