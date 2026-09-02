# Active Directory — runbook des erreurs de connexion

Toutes les erreurs ci-dessous viennent de tests réels — refresh **v3.2.0**
(2026-09-02) contre un vrai DC de lab (Windows Server 2022). Détail complet
(commandes, sorties collées) : `docs/rejeu-doc/docs/BILAN-T140.md`. Une
divergence trouvée lors de cette revalidation est documentée sous
[`LDAP_TLS_VERSION_MISMATCH`](#erreur--tls-protocol-version-not-supported)
ci-dessous. Format constant :

```
### Erreur: <message exact tel que vous le voyez>
Code   : LDAP_XXX_YYY (machine-readable)
Cause  : explication courte
Vérif  : commande pour confirmer
Fix    : procédure
```

> Pour le choix du mode (LDAP/LDAPS/StartTLS), voir [ad-connection-modes.md](ad-connection-modes.md).
> Pour extraire/installer la CA, voir [ad-tls-certificates.md](ad-tls-certificates.md).

---

## Codes d'erreur (table de référence)

À partir de v3.0.21, le collecteur classifie chaque erreur LDAP avec un **code stable**. Le code est :

- Préfixé `[LDAP_XXX]` dans la sortie CLI
- Présent dans `result.error.code` dans les réponses SaaS daemon (`RUN_AUDIT_AD`, `TEST_CONNECTION_AD`, `UPDATE_CONFIG_AD`)
- Présent dans `body.code` des réponses HTTP admin API (`POST /api/v1/admin/ldap/test`)

Tout consommateur (SaaS UI, monitoring, custom dashboard) peut router chaque code vers le bon hint UI / lien doc sans parser le message texte.

| Code | Section |
|---|---|
| `LDAP_TLS_UNKNOWN_AUTHORITY` | [x509: certificate signed by unknown authority](#erreur--x509-certificate-signed-by-unknown-authority) |
| `LDAP_TLS_IP_SAN_MISSING` | [doesn't contain any IP SANs](#erreur--x509-cannot-validate-certificate-for-xxx-because-it-doesnt-contain-any-ip-sans) |
| `LDAP_TLS_HOSTNAME_MISMATCH` | [certificate is valid for X, not Y](#erreur--x509-certificate-is-valid-for-x-not-y) |
| `LDAP_TLS_CERT_EXPIRED` | [certificate expired](#erreur--x509-certificate-has-expired-or-is-not-yet-valid) |
| `LDAP_TLS_VERSION_MISMATCH` | [protocol version not supported](#erreur--tls-protocol-version-not-supported) |
| `LDAP_BIND_INVALID_CREDENTIALS` | [Result Code 49 (data 52e)](#erreur--ldap-result-code-49-invalid-credentials) |
| `LDAP_BIND_ACCOUNT_DISABLED` | [Result Code 49 (data 533)](#erreur--ldap-result-code-49-invalid-credentials) |
| `LDAP_BIND_PASSWORD_EXPIRED` | [Result Code 49 (data 532)](#erreur--ldap-result-code-49-invalid-credentials) |
| `LDAP_BIND_ACCOUNT_LOCKED` | [Result Code 49 (data 775)](#erreur--ldap-result-code-49-invalid-credentials) |
| `LDAP_BIND_LOGON_TIME_RESTRICTED` | [Result Code 49 (data 530)](#erreur--ldap-result-code-49-invalid-credentials) |
| `LDAP_BIND_WORKSTATION_RESTRICTED` | [Result Code 49 (data 531)](#erreur--ldap-result-code-49-invalid-credentials) |
| `LDAP_BIND_MUST_CHANGE_PASSWORD` | [Result Code 49 (data 773)](#erreur--ldap-result-code-49-invalid-credentials) |
| `LDAP_BIND_ACCOUNT_EXPIRED` | [Result Code 49 (data 701)](#erreur--ldap-result-code-49-invalid-credentials) |
| `LDAP_CHANNEL_BINDING_REQUIRED` | [Channel binding requis](#channel-binding-requis-ldapenforcechannelbinding2) |
| `LDAP_STRONG_AUTH_REQUIRED` | [Strong Auth Required](#erreur--ldap-result-code-8-strong-auth-required) |
| `LDAP_REFERRAL_BAD_BASE_DN` | [Referral](#erreur--ldap-result-code-10-referral) |
| `LDAP_NO_SUCH_OBJECT` | [No Such Object](#erreur--ldap-result-code-32-no-such-object) |
| `LDAP_CONNECTION_REFUSED` | [connection refused](#erreur--dial-tcp-xxx636-connection-refused) |
| `LDAP_CONNECTION_TIMEOUT` | [i/o timeout](#erreur--dial-tcp-xxx636-io-timeout) |
| `LDAP_URL_INVALID_SCHEME` | [Unknown scheme](#erreur--unknown-scheme-x) |
| `LDAP_CA_CERT_FILE_NOT_FOUND` *(v3.1.12)* | [ca-cert path not readable](#erreur--ldap_ca_cert_file_not_found---ldap-ca-cert-path-is-not-readable) |
| `LDAP_CA_CERT_INVALID_PEM` *(v3.1.12)* | [ca-cert content not valid PEM](#erreur--ldap_ca_cert_invalid_pem---ldap-ca-cert-file-contents-are-not-a-valid-pem-certificate) |
| `LDAP_TLS_INVALID_MIN_VERSION` *(v3.1.12)* | [tls-min-version invalid](#erreur--ldap_tls_invalid_min_version---ldap-tls-min-version-value-is-invalid) |
| `LDAP_UNKNOWN_ERROR` | Fallback (erreur non classifiée) |

### Sortie CLI (exemple v3.0.21+)

```
Error: LDAP connection failed:
[LDAP_TLS_UNKNOWN_AUTHORITY] LDAP server certificate is not trusted by the client
  → Fix:  Install the DC's root CA in the system trust store, or pass --ldap-ca-cert /path/to/ca.pem.
  → Docs: docs/configuration/ad-troubleshooting.md#erreur--x509-certificate-signed-by-unknown-authority
  → Raw:  LDAP Result Code 200 "Network Error": tls: failed to verify certificate: x509: certificate signed by unknown authority
```

### Payload SaaS (exemple)

```json
{
  "status": "error",
  "error": {
    "code": "LDAP_TLS_UNKNOWN_AUTHORITY",
    "message": "LDAP server certificate is not trusted by the client",
    "details": "Resolution: Install the DC's root CA ...\nDocs: docs/configuration/ad-troubleshooting.md#erreur--x509-certificate-signed-by-unknown-authority\nRaw: x509: certificate signed by unknown authority"
  }
}
```

---

## Diag rapide en 4 commandes

Avant de plonger dans une erreur spécifique :

```bash
# 1. DNS
nslookup dc01.example.com

# 2. Port 636 atteignable
nc -zv dc01.example.com 636
# (Windows : Test-NetConnection dc01.example.com -Port 636)

# 3. Cert serveur valide pour ce nom
openssl s_client -connect dc01.example.com:636 -servername dc01.example.com -verify 5 < /dev/null 2>&1 \
  | grep -E "Verification|subject="

# 4. Bind LDAPS marche en cross-check
ldapsearch -H ldaps://dc01.example.com:636 \
  -D "CN=svc-audit,CN=Users,DC=example,DC=com" \
  -W -b "DC=example,DC=com" -s base
```

---

## Erreurs TLS / certificat

### Erreur : `x509: certificate signed by unknown authority`

**Code** : `LDAP_TLS_UNKNOWN_AUTHORITY`

**Sortie complète (Linux/Windows)** :
```
Error: connect to LDAP: ldap: connect: LDAP Result Code 200 "Network Error":
  tls: failed to verify certificate: x509: certificate signed by unknown authority
```

**Sortie complète (macOS)** :
```
Error: connect to LDAP: ldap: connect: LDAP Result Code 200 "Network Error":
  tls: failed to verify certificate: x509: "dc01.example.com" certificate is not trusted
```

**Cause** : le truststore système ne contient pas la CA racine qui a signé le cert serveur du DC. Cela arrive notamment quand :
- Vous lancez le collecteur depuis une machine non jointe au domaine
- Le cert serveur est auto-signé (lab)
- La CA est privée (Enterprise CA AD CS) et n'est pas dans le store local

**Vérification** :
```bash
openssl s_client -connect dc01.example.com:636 -servername dc01.example.com < /dev/null 2>&1 \
  | grep -E "subject=|issuer="
```

Si l'`issuer=` n'est pas visible dans `Get-ChildItem Cert:\LocalMachine\Root` (Windows) ou `/etc/ssl/certs/` (Linux), c'est confirmé.

**Fix** : installer la CA. Voir [ad-tls-certificates.md#5-installer-la-ca-pour-que-le-collecteur-la-trouve](ad-tls-certificates.md#5-installer-la-ca-pour-que-le-collecteur-la-trouve).

**Workaround temporaire** (à éviter en prod) :
```bash
etc-collector audit ad ... --ldap-tls-verify=false
```

---

### Erreur : `x509: cannot validate certificate for X.X.X.X because it doesn't contain any IP SANs`

**Code** : `LDAP_TLS_IP_SAN_MISSING`

**Sortie complète** :
```
Error: connect to LDAP: ldap: connect: LDAP Result Code 200 "Network Error":
  tls: failed to verify certificate: x509: cannot validate certificate for 192.0.2.10
  because it doesn't contain any IP SANs
```

**Cause** : vous avez utilisé `--ldap-url ldaps://192.0.2.10:636` (IP) mais le cert serveur n'a que des SAN DNS (typique en AD : SAN = `dc01.example.com`, pas l'IP).

**Vérification** :
```bash
openssl s_client -connect 192.0.2.10:636 < /dev/null 2>&1 \
  | openssl x509 -noout -text | grep -A1 "Subject Alternative Name"
# Attendu : "DNS:dc01.example.com" — pas de "IP Address:..."
```

**Fix** : utiliser le FQDN qui est listé dans le SAN du cert.

```bash
# Au lieu de :
--ldap-url ldaps://192.0.2.10:636
# Utiliser :
--ldap-url ldaps://dc01.example.com:636
```

Si le DNS ne résout pas, ajoutez une entrée `/etc/hosts` (Linux/macOS) ou `C:\Windows\System32\drivers\etc\hosts` (Windows) :
```
192.0.2.10  dc01.example.com
```

---

### Erreur : `x509: certificate is valid for X, not Y`

**Code** : `LDAP_TLS_HOSTNAME_MISMATCH`

**Sortie complète** :
```
Error: connect to LDAP: ldap: connect: LDAP Result Code 200 "Network Error":
  tls: failed to verify certificate: x509: certificate is valid for dc01.example.com,
  not localhost
```

**Cause** : le hostname dans `--ldap-url` ne correspond à aucun SAN du cert serveur.

**Vérification** : voir SAN du cert (commande au-dessus).

**Fix** : utiliser exactement un des noms listés dans les SAN. Si le cert n'a pas le nom voulu, soit régénérer le cert côté DC (rôle PKI), soit utiliser un autre nom.

---

### Erreur : `x509: certificate has expired or is not yet valid`

**Code** : `LDAP_TLS_CERT_EXPIRED`

**Cause** : cert serveur du DC expiré ou pas encore valide (heure système décalée).

**Vérification** :
```bash
openssl s_client -connect dc01.example.com:636 < /dev/null 2>/dev/null \
  | openssl x509 -noout -dates
# notBefore=... notAfter=...

# Heure du collecteur
date -u
```

**Fix** :
- Cert expiré → renouveler côté DC (auto-enrollment AD CS, ou demander à l'équipe PKI)
- Heure décalée → synchroniser NTP côté collecteur (`timedatectl set-ntp true` sur Linux)

---

### Erreur : `tls: protocol version not supported`

**Code** : `LDAP_TLS_VERSION_MISMATCH`

**Cause** : `tlsMinVersion` configuré à une valeur que le DC ne supporte pas (ex : 1.3 sur un DC qui ne fait que 1.2).

**Vérification** : tester quelle version TLS le DC offre :
```bash
openssl s_client -connect dc01.example.com:636 -tls1_3 < /dev/null 2>&1 | grep -E "Protocol|wrong version"
openssl s_client -connect dc01.example.com:636 -tls1_2 < /dev/null 2>&1 | grep "Protocol"
```

**Fix** : aligner `tlsMinVersion` sur ce que le DC supporte (généralement `"1.2"` est sûr pour Windows Server 2016+).

> ⚠️ **Constaté le 2026-09-02 contre un vrai DC Windows Server 2022** : ce
> scénario (`--ldap-tls-min-version 1.3` sur un DC qui ne le négocie pas) ne
> produit **pas** `[LDAP_TLS_VERSION_MISMATCH]` mais `[LDAP_UNKNOWN_ERROR]`
> avec un `Raw` du type `read: connection reset by peer`. Le DC refuse le
> `ClientHello` TLS 1.3 par un reset TCP brut plutôt que par l'alerte TLS
> propre (`tls: protocol version not supported`) que le classifieur attend —
> comportement Schannel réel, pas un artefact de lab. **Si vous voyez un
> `LDAP_UNKNOWN_ERROR` avec `connection reset by peer` juste après avoir
> passé `--ldap-tls-min-version`, appliquez quand même le Fix ci-dessus** :
> c'est la cause la plus probable. Gap de classification signalé à l'équipe
> produit (`M_021_ldap-tls-version-mismatch-classifier-gap`, T_140).

---

## Erreurs LDAP (post-TLS)

### Erreur : `LDAP Result Code 49 "Invalid Credentials"`

**Code** (selon le `data XXX` dans le message) :

| `data` AD | Code structuré du collecteur |
|---|---|
| `52e` (défaut) | `LDAP_BIND_INVALID_CREDENTIALS` |
| `533` | `LDAP_BIND_ACCOUNT_DISABLED` |
| `532` | `LDAP_BIND_PASSWORD_EXPIRED` |
| `775` | `LDAP_BIND_ACCOUNT_LOCKED` |
| `530` | `LDAP_BIND_LOGON_TIME_RESTRICTED` |
| `531` | `LDAP_BIND_WORKSTATION_RESTRICTED` |
| `773` | `LDAP_BIND_MUST_CHANGE_PASSWORD` |
| `701` | `LDAP_BIND_ACCOUNT_EXPIRED` |
| `80090346` | `LDAP_CHANNEL_BINDING_REQUIRED` |

**Sortie complète** :
```
Error: connect to LDAP: ldap: bind: LDAP Result Code 49 "Invalid Credentials":
  80090308: LdapErr: DSID-0C090434, comment: AcceptSecurityContext error,
  data 52e, v4f7c
```

**Cause** : `data 52e` = bad password OU bad account. Le serveur AD ne distingue pas les deux par sécurité.

**Codes d'erreur AD courants** (après `data ` dans le message) :

| Code | Sens |
|---|---|
| `52e` | Mauvais mot de passe ou compte inexistant |
| `525` | Compte inexistant (rare, en général AD donne 52e) |
| `530` | Restriction d'horaire de logon |
| `531` | Restriction de poste de logon |
| `532` | Mot de passe expiré |
| `533` | Compte désactivé |
| `701` | Compte expiré |
| `773` | Doit changer le mot de passe au prochain logon |
| `775` | Compte verrouillé |

**Vérification** :
```powershell
# Côté DC, voir l'événement de bind échoué
Get-WinEvent -LogName Security -MaxEvents 20 -FilterHashtable @{Id=4625} |
  Format-List TimeCreated, Message
```

```bash
# Cross-check avec ldapsearch
ldapsearch -H ldaps://dc01.example.com:636 \
  -D "CN=svc-audit,CN=Users,DC=example,DC=com" -W -b "" -s base
```

**Fix** :
- Vérifier la valeur exacte de `--ldap-bind-dn` (typo dans CN, OU, DC parts)
- Vérifier le mot de passe (caractères spéciaux à échapper en shell, ou les passer via env var)
- Vérifier que le compte n'est pas verrouillé / expiré

---

### Erreur : `LDAP Result Code 8 "Strong Auth Required"`

**Code** : `LDAP_STRONG_AUTH_REQUIRED`

**Cause** : le DC refuse les binds non-signés (signing enforced via `LDAPServerIntegrity=2`). Vous tentez un bind LDAP plain sur :389 sans LDAPS ni Kerberos.

**Vérification (côté DC)** :
```powershell
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" |
  Select LDAPServerIntegrity
# 2 = Required, 1 = Negotiate (défaut)
```

**Fix** : passer en LDAPS :
```bash
--ldap-url ldaps://dc01.example.com:636
```

---

### Erreur : `LDAP Result Code 10 "Referral"`

**Code** : `LDAP_REFERRAL_BAD_BASE_DN`

**Sortie complète** :
```
Error: audit failed: ldap: get users: LDAP Result Code 10 "Referral":
  0000202B: RefErr: DSID-03100838, data 0, 1 access points
    ref 1: 'wrong.cc'
```

**Cause** : `--ldap-base-dn` pointe vers un domaine que ce DC ne gère pas. Le DC répond par un referral vers le DC qui devrait gérer ce baseDN.

**Vérification** :
```bash
# Lister les naming contexts gérés par ce DC
ldapsearch -H ldaps://dc01.example.com:636 \
  -D "CN=svc,CN=Users,DC=example,DC=com" -W \
  -b "" -s base -- "namingContexts"
```

**Fix** : utiliser le `defaultNamingContext` du DC. Pour `example.com` :
```bash
--ldap-base-dn "DC=example,DC=cc"
# (et non "DC=wrong,DC=cc" qui produit le referral)
```

---

### Erreur : `LDAP Result Code 32 "No Such Object"`

**Code** : `LDAP_NO_SUCH_OBJECT`

**Cause** : le baseDN existe sur ce DC mais sa valeur est mal formée (ex : `DC=example,DC=com,DC=local`), ou la cible cherchée (`get users`) n'est pas trouvable sous ce DN.

**Vérification** :
```bash
ldapsearch -H ldaps://dc01.example.com:636 -D "..." -W -b "DC=example,DC=com" -s base
# Si réponse vide ou code 32 → base DN incorrect
```

**Fix** : utiliser le DN correct (souvent celui retourné par `defaultNamingContext`).

---

### Erreur : Bind OK mais audit avec 0 résultats

**Cause** : le baseDN est valide mais ne couvre pas l'OU où sont les comptes (ex : baseDN = `OU=Servers,DC=example,DC=com` au lieu de `DC=example,DC=com`).

**Fix** : utiliser le DN racine du domaine :
```bash
--ldap-base-dn "DC=example,DC=com"
```

Le collecteur effectue des recherches `LDAP_SCOPE_SUBTREE` à partir du baseDN ; si vous limitez à une OU, vous excluez tout ce qui est ailleurs.

---

## Erreurs réseau

### Erreur : `dial tcp X.X.X.X:636: connection refused`

**Code** : `LDAP_CONNECTION_REFUSED`

**Sortie complète (Windows)** :
```
Error: connect to LDAP: ldap: connect: LDAP Result Code 200 "Network Error":
  dial tcp [::1]:6360: connectex: No connection could be made because the target
  machine actively refused it.
```

**Sortie complète (Linux)** :
```
Error: connect to LDAP: ldap: connect: LDAP Result Code 200 "Network Error":
  dial tcp 192.0.2.10:6360: connect: connection refused
```

**Cause** : la machine cible répond TCP RST sur ce port. Soit :
- Le port est faux (vous avez tapé `:6360` au lieu de `:636`)
- Le DC n'a pas de service LDAPS bindé (Schannel sans cert valide — voir [ad-tls-certificates.md#7-cas-particulier--dc-sans-certificat-ldaps](ad-tls-certificates.md#7-cas-particulier--dc-sans-certificat-ldaps))

> Constaté le 2026-09-02 sur un vrai DC Windows : viser un port fermé
> (`:6360` au lieu de `:636`) y a produit un **`LDAP_CONNECTION_TIMEOUT`**,
> pas ce code — le Pare-feu Windows local **droppe** silencieusement les
> paquets vers un port non écouté au lieu d'émettre un RST. `REFUSED`
> suppose une pile TCP qui répond activement (typique hors pare-feu Windows,
> ou sur un service qui écoute mais refuse la connexion applicative) ; sur un
> DC Windows durci, un port fermé se manifeste plus souvent comme un
> [timeout](#erreur--dial-tcp-xxx636-io-timeout) que comme ce refus.

**Vérification** :
```bash
# Le service écoute-t-il vraiment sur ce port ?
nc -zv dc01.example.com 636      # Linux/macOS
Test-NetConnection dc01 -Port 636  # Windows

# Côté DC :
Get-NetTCPConnection -State Listen | Where-Object { $_.LocalPort -in 389,636 }
```

**Fix** : utiliser le bon port (636 pour LDAPS, 389 pour LDAP/StartTLS) et s'assurer que le DC l'expose.

---

### Erreur : `dial tcp X.X.X.X:636: i/o timeout`

**Code** : `LDAP_CONNECTION_TIMEOUT`

**Sortie complète** :
```
Error: connect to LDAP: ldap: connect: LDAP Result Code 200 "Network Error":
  dial tcp 192.0.2.99:636: connectex: A connection attempt failed because the
  connected party did not properly respond after a period of time, or established
  connection failed because connected host has failed to respond.
```

**Cause** : firewall sur le chemin (DC down, route bloquée, NAT), ou le DC ne répond pas du tout. Différent de "refused" → ici **aucune** réponse, juste un timeout (~21s avec defaults).

**Vérification** :
```bash
# Ping ICMP
ping -c 4 dc01.example.com

# Trace pour voir où ça coupe
traceroute dc01.example.com

# Tentative TCP avec timeout court
nc -zv -w 5 dc01.example.com 636
```

**Fix** :
- DC down → contacter l'équipe AD ops
- Firewall → ouvrir le flux 636/TCP entre collecteur et DC
- DNS résout vers une mauvaise IP → vérifier `nslookup` et corriger

---

### Erreur : `Unknown scheme 'X'`

**Code** : `LDAP_URL_INVALID_SCHEME`

**Sortie complète** :
```
Error: connect to LDAP: ldap: connect: LDAP Result Code 200 "Network Error":
  Unknown scheme 'dc01.example.com'
```

**Cause** : `--ldap-url` ne commence pas par `ldap://` ou `ldaps://`. Vous avez probablement écrit juste le hostname.

**Fix** : ajouter le scheme :
```bash
# Mauvais
--ldap-url dc01.example.com:636

# Bon
--ldap-url ldaps://dc01.example.com:636
```

---

## Cas marginaux

### Channel binding requis (`LdapEnforceChannelBinding=2`)

**Code** : `LDAP_CHANNEL_BINDING_REQUIRED`

Symptôme attendu (non testé en lab, basé sur la doc Microsoft) :
```
LDAP Result Code 49 "Invalid Credentials": ... data 80090346 ...
```
ou
```
Channel binding required by server
```

**Cause** : le DC enforce le channel binding TLS (LDAP signing + binding au cert TLS). Le binaire actuel n'implémente pas le channel binding LDAP.

**Vérification (côté DC)** :
```powershell
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" |
  Select LdapEnforceChannelBinding
# 0 = jamais, 1 = quand supporté, 2 = toujours requis
```

**Fix** : aujourd'hui, demander à l'équipe AD de baisser à `1` (compatibilité) si possible. Le support du channel binding côté collecteur est un item backlog.

---

### LDAP signing enforced (`LDAPServerIntegrity=2`)

Voir [erreur LDAP Result Code 8 "Strong Auth Required"](#erreur--ldap-result-code-8-strong-auth-required) ci-dessus. Workaround : passer en LDAPS direct.

---

### Cert serveur DC avec chaîne intermédiaire

Si votre PKI utilise une CA racine + une CA intermédiaire émettrice :

```
example-Root-CA → example-Issuing-CA → DC server cert
```

Vous devez fournir **les deux** (root + intermediate) dans le PEM, ou installer les deux dans le truststore système.

PEM concaténé :
```
-----BEGIN CERTIFICATE-----
(intermediate CA)
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
(root CA)
-----END CERTIFICATE-----
```

---

## Quoi faire si rien ne marche

1. Lancer la commande avec `-V` (verbose) :
   ```bash
   etc-collector audit ad -V --ldap-url ldaps://dc01:636 ...
   ```
2. Capturer la sortie complète :
   ```bash
   etc-collector audit ad ... 2>&1 | tee /tmp/audit-debug.log
   ```
3. Cross-checker avec `ldapsearch` standard :
   ```bash
   ldapsearch -d 1 -H ldaps://dc01:636 -D "..." -W -b "DC=...,DC=..." -s base 2>&1 | head -50
   ```
4. Comparer le truststore vu par le binaire vs ce que `openssl s_client` négocie.
5. Si toujours rien, ouvrir un ticket avec : version (`etc-collector --version`), commande exacte (mot de passe masqué), output verbose, sortie de `openssl s_client` sur le DC.

---

## Codes ajoutés en v3.1.12

Les 3 codes ci-dessous ont été ajoutés en v3.1.12 — toutes les anciennes erreurs `LDAP_UNKNOWN_ERROR` correspondantes émettent maintenant un code structuré dédié.

### Erreur : `[LDAP_CA_CERT_FILE_NOT_FOUND] --ldap-ca-cert path is not readable`

**Cause** : le chemin passé à `--ldap-ca-cert` n'existe pas ou n'est pas lisible par le compte qui exécute le collecteur.

**Trigger** : `--ldap-ca-cert /nonexistent.pem` ou `--ldap-ca-cert C:\nope.pem`.

**Avant v3.1.12** : silencieusement ignoré, fallback sur le truststore système — l'admin pensait avoir épinglé une CA spécifique alors qu'elle était droppée.

**Fix utilisateur** :
1. Vérifier le chemin exact : `Test-Path C:\rootca.pem` (PowerShell) ou `ls -l /etc/etc-collector/rootca.pem` (Linux).
2. Vérifier les permissions (le compte qui lance ETC doit pouvoir lire le fichier).
3. Privilégier un chemin **absolu** plutôt que relatif.

### Erreur : `[LDAP_CA_CERT_INVALID_PEM] --ldap-ca-cert file contents are not a valid PEM certificate`

**Cause** : le fichier existe et est lu, mais son contenu n'est pas un certificat PEM valide. Cas typique : fichier DER (binaire `.cer`/`.crt`) au lieu de PEM (texte `-----BEGIN CERTIFICATE-----`).

**Trigger** : `--ldap-ca-cert /tmp/cert.der`.

**Fix utilisateur** :
- Convertir DER → PEM :
  ```bash
  openssl x509 -inform der -in cert.der -out cert.pem
  ```
- Ou ouvrir le fichier — il doit commencer par `-----BEGIN CERTIFICATE-----`.

### Erreur : `[LDAP_TLS_INVALID_MIN_VERSION] --ldap-tls-min-version value is invalid`

**Cause** : la valeur de `--ldap-tls-min-version` n'est pas dans `{1.0, 1.1, 1.2, 1.3}`.

**Trigger** : `--ldap-tls-min-version 1.4` ou `--ldap-tls-min-version xxx`.

**Avant v3.1.12** : retournait `LDAP_UNKNOWN_ERROR` au handshake, peu utile pour diagnostiquer.

**Fix utilisateur** : utiliser une des 4 valeurs supportées. Par défaut (flag absent) = TLS 1.2.

---

## Erreur : `[LDAP_REFERRAL_BAD_BASE_DN] Base DN is not served by this DC`

Apparaît quand `--ldap-base-dn` ne correspond pas au domaine du DC ciblé.

**Trigger** : `--ldap-base-dn DC=fake,DC=domain` alors que le DC sert `DC=example,DC=cc`.

**Avant v3.1.12** : remontait sous forme brute `LDAP Result Code 10 "Referral"` sans classification (la classification existait pour la phase bind mais pas post-bind). Depuis v3.1.12, toutes les erreurs LDAP d'audit (`get users`, `get groups`, etc.) sont classifiées via le hook `RegisterClassifier` côté `providers/`.

**Fix utilisateur** :
```powershell
# Sur un poste joint au domaine
(Get-ADDomain).DistinguishedName
# Sortie : DC=example,DC=com

# Ou via rootDSE
ldapsearch -H ldaps://dc01:636 -x -s base -b "" defaultNamingContext
```
