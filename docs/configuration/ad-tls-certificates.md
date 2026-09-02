# Active Directory — extraire et installer les certificats TLS

Le collecteur valide la chaîne X.509 du certificat présenté par le DC en LDAPS (port 636) ou en LDAP+StartTLS. Cette page explique **comment récupérer la bonne CA** et **comment l'installer** pour que la validation TLS passe.

> Pour les erreurs de connexion, voir [ad-troubleshooting.md](ad-troubleshooting.md).
> Pour le choix du mode (LDAP/LDAPS/StartTLS), voir [ad-connection-modes.md](ad-connection-modes.md).

---

## 1. Quel certificat il vous faut

Une connexion LDAPS implique 3 acteurs :

```
[Collecteur]  ←──── TLS handshake ────→  [DC sur :636]
                                          │
                                          │ présente : cert serveur
                                          │   subject: CN=dc01.example.com
                                          │   issuer:  CN=example-Root-CA
                                          ▼
                                    [chaîne signature]
                                          │
                                          ▼
                                    [Root CA: example-Root-CA]
                                    auto-signée (root) ou
                                    signée par CA intermédiaire
```

**Ce dont le collecteur a besoin** : la **CA racine** (parfois aussi la chaîne intermédiaire) qui a signé le cert serveur du DC. Le cert serveur du DC lui-même n'a **pas** besoin d'être installé.

Dans 95% des AD, l'organisation a une **AD CS Enterprise CA** (rôle "Active Directory Certificate Services" sur un serveur Windows). Cette CA racine signe automatiquement les certs des DC via le template `Domain Controller` ou `Kerberos Authentication`.

### Comment savoir si vous avez une AD CS dans votre forêt

```powershell
# Côté DC ou poste joint au domaine :
Get-ADObject -Filter * -SearchBase "CN=Public Key Services,CN=Services,$((Get-ADRootDSE).configurationNamingContext)" -SearchScope OneLevel
# Si ça retourne des objets dont CN=Enrollment Services, il y a une AD CS
```

### Cas particulier : DC avec cert **auto-signé** (pas d'AD CS)

Certains DC en lab ont un cert auto-signé généré par Schannel. Dans ce cas, le cert serveur **est lui-même** sa propre racine — exportez-le directement (méthode A ci-dessous donne le cert leaf, qui suffit comme "CA" puisque self-signed).

---

## 2. Cinq méthodes pour extraire la CA

### Méthode A — `openssl s_client` (Linux / macOS / Windows avec OpenSSL)

Marche depuis n'importe quelle machine ayant accès au DC sur 636. **Méthode la plus rapide**.

```bash
# Récupère tous les certs présentés (cert serveur + intermédiaires si fournis)
openssl s_client -connect dc01.example.com:636 -showcerts -servername dc01.example.com < /dev/null \
  2>/dev/null | awk '/-----BEGIN/,/-----END/' > dc-chain.pem

# Vérifier
openssl x509 -in dc-chain.pem -noout -subject -issuer -dates
```

**Important** : un DC AD CS standard ne renvoie **que** le cert serveur (pas la CA dans le chain), parce que le client AD a la CA dans son truststore Schannel. Donc `dc-chain.pem` contient juste le cert serveur — pas la CA.

Pour récupérer la CA racine, il faut donc passer par les méthodes B/C/D depuis un poste qui l'a déjà.

### Méthode B — PowerShell sur le DC ou un poste joint

```powershell
# Trouve la CA racine de votre forêt (commence par "yourdomain-CA-XXX-CA" en général)
Get-ChildItem Cert:\LocalMachine\Root |
  Where-Object { $_.Subject -like "*CA*" -and $_.Subject -like "*$env:USERDNSDOMAIN*" } |
  Select Subject, NotAfter, Thumbprint

# Exporter en DER (.cer)
$ca = Get-ChildItem Cert:\LocalMachine\Root |
  Where-Object { $_.Subject -like "*example-Root-CA*" } | Select-Object -First 1
Export-Certificate -Cert $ca -FilePath C:\temp\ca.cer -Type CERT

# Convertir en PEM
$pem = "-----BEGIN CERTIFICATE-----`n" +
       [Convert]::ToBase64String($ca.RawData, 'InsertLineBreaks') +
       "`n-----END CERTIFICATE-----"
$pem | Out-File -Encoding ASCII C:\temp\ca.pem
```

Exemple sur le lab `example.com` (sortie réelle) :

```
Subject                              NotAfter              Thumbprint
-------                              --------              ----------
CN=example-dc01-CA, DC=example, DC=cc 11/17/2030 2:08:03 PM FBAB015B0E8BA4D6715BB3FDA1225AD0AB547022
```

### Méthode C — AD CS Web Enrollment

Si le rôle **AD CS Web Enrollment** est installé sur la CA :

```
https://ca.example.com/certsrv/certcarc.asp
```

→ "Download CA certificate chain" (option `Base64` pour PEM).

### Méthode D — `certutil` sur le serveur AD CS

Sur le serveur Windows qui héberge la CA :

```cmd
:: Exporte le cert de la CA en cours d'utilisation
certutil -ca.cert ca.cer

:: Si plusieurs CA existent, lister les versions :
certutil -ca.cert -? 

:: Convertir en PEM :
certutil -encode ca.cer ca.pem
```

### Méthode E — Console MMC (`certmgr.msc`)

1. `Start` → `certmgr.msc` (sur un poste joint au domaine)
2. **Trusted Root Certification Authorities** → **Certificates**
3. Trouver la CA (généralement `<domain>-<ServerName>-CA`)
4. Clic droit → **All Tasks** → **Export**
5. Choisir **Base-64 encoded X.509 (.CER)** — c'est du PEM avec extension `.cer`
6. Renommer en `.pem` après export pour clarté

---

## 3. Conversion DER ↔ PEM

| Format | Contenu | Extension typique | Reconnu par le collecteur |
|---|---|---|---|
| **PEM** | Texte ASCII Base64, encadré `-----BEGIN/END CERTIFICATE-----` | `.pem`, `.crt`, parfois `.cer` | ✓ |
| **DER** | Binaire pur | `.cer`, `.der` | ✗ (convertir d'abord) |

```bash
# Identifier le format actuel
file ca.cer
# "ca.cer: PEM certificate"  → déjà PEM
# "ca.cer: data"             → probablement DER

# DER → PEM
openssl x509 -in ca.cer -inform DER -out ca.pem -outform PEM

# PEM → DER (rarement utile pour le collecteur)
openssl x509 -in ca.pem -inform PEM -out ca.cer -outform DER
```

---

## 4. Vérifier que la chaîne est correcte

```bash
# Récupérer le cert serveur du DC
openssl s_client -connect dc01.example.com:636 -servername dc01.example.com < /dev/null \
  2>/dev/null | openssl x509 -outform PEM > dc-server.pem

# Vérifier que la CA fournie valide bien le cert serveur
openssl verify -CAfile ca.pem dc-server.pem
# Attendu : "dc-server.pem: OK"
```

Si vous obtenez `unable to get local issuer certificate`, la CA fournie n'est **pas** celle qui a signé le cert serveur. Voir [troubleshooting](ad-troubleshooting.md#erreur--x509-certificate-signed-by-unknown-authority).

Test de bout-en-bout (valide la chaîne ET la connexion) :

```bash
openssl s_client -connect dc01.example.com:636 \
  -servername dc01.example.com -CAfile ca.pem -verify 5 < /dev/null 2>&1 | grep -E "Verify|verify"
# Attendu : "Verification: OK" et "Verify return code: 0 (ok)"
```

---

## 5. Installer la CA pour que le collecteur la trouve

À partir de **v3.0.21**, toutes les options TLS (`tlsCACert`, `tlsCACertPEM`, `startTLS`, `tlsMinVersion`) sont supportées partout : CLI `audit ad`, mode `server`, SaaS daemon, API admin GUI et mode `trial`. Voir [ad-connection-modes.md](ad-connection-modes.md#options-tls-exposées-v3021).

Trois chemins d'installation, par ordre de simplicité :

### Option 1 — Truststore système (zéro option à configurer)

Pratique quand vous gérez plusieurs clients TLS sur la machine ou que la CA doit être partagée.

#### Linux (Debian / Ubuntu)

```bash
sudo cp ca.pem /usr/local/share/ca-certificates/example-root-ca.crt
sudo update-ca-certificates
# → "1 added, 0 removed; done."
```

#### Linux (RHEL / CentOS / Fedora)

```bash
sudo cp ca.pem /etc/pki/ca-trust/source/anchors/example-root-ca.crt
sudo update-ca-trust
```

#### macOS

```bash
sudo security add-trusted-cert -d -r trustRoot \
  -k /Library/Keychains/System.keychain ca.pem
```

#### Windows

```powershell
# En administrateur
certutil -addstore -f Root C:\path\to\ca.cer
# Vérifier
Get-ChildItem Cert:\LocalMachine\Root | Where-Object { $_.Subject -like "*example-Root-CA*" }
```

Après installation, n'importe quel binaire Go (donc `etc-collector`) fait confiance à cette CA via les API standard `x509.SystemCertPool()`.

### Option 2 — Fichier PEM via flag CLI ou YAML (recommandé pour usage one-shot)

#### CLI

```bash
etc-collector audit ad \
  --ldap-url ldaps://dc01.example.com:636 \
  --ldap-ca-cert /etc/etc-collector/ca.pem \
  --ldap-bind-dn "..." --ldap-bind-password "..." --ldap-base-dn "..."
```

#### Env var (pour Docker / Kubernetes)

```bash
export LDAP_TLS_CA_CERT=/etc/etc-collector/ca.pem
etc-collector audit ad --ldap-url ldaps://dc01.example.com:636 ...
```

#### YAML (pour `server` mode et SaaS daemon)

```yaml
ldap:
  url: "ldaps://dc01.example.com:636"
  bindDN: "CN=svc-audit,CN=Users,DC=example,DC=com"
  bindPassword: "${LDAP_BIND_PASSWORD}"
  baseDN: "DC=example,DC=com"
  tlsVerify: true
  tlsCACert: "/etc/etc-collector/ca.pem"   # chemin absolu
```

### Option 3 — PEM inline dans la config (idéal Kubernetes / SaaS)

Utile pour Kubernetes / SaaS où vous ne voulez pas gérer un fichier séparé.

```yaml
ldap:
  url: "ldaps://dc01.example.com:636"
  bindDN: "CN=svc-audit,CN=Users,DC=example,DC=com"
  bindPassword: "${LDAP_BIND_PASSWORD}"
  baseDN: "DC=example,DC=com"
  tlsVerify: true
  tlsCACertPEM: |
    -----BEGIN CERTIFICATE-----
    MIIDZzCCAk+gAwIBAgIQ...  (toute la PEM)
    ...
    -----END CERTIFICATE-----
```

Le contenu est détecté automatiquement comme PEM inline dès qu'il commence par `-----BEGIN`.

---

## 6. Schéma type d'AD CS

```
                    ┌───────────────────────┐
                    │  Enterprise Root CA   │   ← AD CS rôle, souvent sur un DC ou serveur dédié
                    │  CN=example-Root-CA   │     (cert auto-signé, valide ~5-10 ans)
                    └──────────┬────────────┘
                               │
                               │  signe via template
                               │  "Domain Controller" ou
                               │  "Kerberos Authentication"
                               ▼
                    ┌───────────────────────┐
                    │   Cert serveur DC      │   ← présent dans LocalMachine\My du DC
                    │   CN=dc01.example.com  │     auto-bindé sur :636 par Schannel
                    │   SAN: DNS:dc01.example.com │
                    └───────────────────────┘
```

Ce que vous donnez au collecteur = la **CA racine** (cadre du haut).
Ce que le collecteur reçoit du DC en LDAPS = le **cert serveur** (cadre du bas).

---

## 7. Cas particulier : DC sans certificat LDAPS

Symptôme : `dial tcp dc01.example.com:636: connection refused` ou le port 636 absent du `Get-NetTCPConnection`.

Cause : Schannel n'a aucun cert valide bindable pour LDAPS. Cela arrive quand :
- AD CS n'est pas déployé dans la forêt
- Le DC n'a jamais reçu de cert via auto-enrollment
- Le cert existant est expiré ou révoqué

Vérification côté DC :

```powershell
# Lister les certs disponibles pour Schannel
Get-ChildItem Cert:\LocalMachine\My | Select Subject, NotAfter, Thumbprint

# Vérifier le binding actif
netsh http show sslcert ipport=0.0.0.0:636
```

Fix rapide en lab : déployer AD CS Enterprise (`Install-WindowsFeature ADCS-Cert-Authority` puis `Install-AdcsCertificationAuthority -CAType EnterpriseRootCA`), puis attendre l'auto-enrollment du DC (forçable avec `gpupdate /force` puis `certutil -pulse`).

En production : créez un ticket avec votre équipe PKI.

---

## 8. Bonus : exporter le cert serveur du DC (pour pinning ou diag)

```bash
# Linux/macOS
openssl s_client -connect dc01.example.com:636 -servername dc01.example.com < /dev/null 2>/dev/null \
  | openssl x509 -outform PEM > dc-server.pem

# Voir tous les attributs
openssl x509 -in dc-server.pem -noout -text | head -40

# SHA1 fingerprint
openssl x509 -in dc-server.pem -noout -fingerprint
```

Utile pour comparer ce que **le DC envoie** vs ce qui est **attendu** dans votre PKI.

---

## 9. Checklist avant de lancer le collecteur en LDAPS

- [ ] DNS résout `dc01.example.com` vers la bonne IP (`nslookup`)
- [ ] Port 636 accessible (`Test-NetConnection` ou `nc -zv`)
- [ ] Cert serveur du DC valide (non expiré, SAN inclut le FQDN utilisé)
- [ ] CA racine accessible (extraite via méthode A-E)
- [ ] CA installée dans le truststore système **OU** `tlsCACert` configuré (selon mode utilisé)
- [ ] Compte de service AD bind-able (testé avec `ldapsearch` ou équivalent)

Test final : voir [ad-connection-modes.md#tester-votre-configuration-en-30-secondes](ad-connection-modes.md#tester-votre-configuration-en-30-secondes).
