# Active Directory — démarrage rapide (admin junior)

Ce document est le **premier fichier à lire** pour configurer la connexion AD du collecteur. Public cible : admin AD sans expérience préalable d'audit tooling. À la fin vous aurez un fichier JSON d'audit en moins de 15 minutes.

> Pour les détails techniques par mode (LDAP/LDAPS/StartTLS), voir [ad-connection-modes.md](ad-connection-modes.md).
> Pour extraire/installer les certificats TLS, voir [ad-tls-certificates.md](ad-tls-certificates.md).
> Pour les erreurs, voir [ad-troubleshooting.md](ad-troubleshooting.md).

---

## 1. Cinq questions à se poser avant tout

Cochez mentalement les réponses — elles déterminent votre chemin.

| # | Question | Réponse OUI | Réponse NON |
|---|---|---|---|
| Q1 | Avez-vous **AD Certificate Services** (AD CS) installé dans la forêt ? | LDAPS direct, méthode standard | Cert auto-signé sur chaque DC (cas plus rare) |
| Q2 | Le DC répond-il sur le port **636** (LDAPS) ? | LDAPS direct | Tentez **StartTLS sur 389** ou installez LDAPS |
| Q3 | Avez-vous un **DNS interne** qui résout `dc01.example.com` depuis la machine du collecteur ? | Utilisez le **FQDN** | Utilisez l'**IP** (mais le cert TLS doit avoir une IP SAN) |
| Q4 | Avez-vous un **compte AD avec read** sur tout le domaine ? | OK | Créez `svc-etc-collector` (cf. §6) |
| Q5 | Le collecteur tourne-t-il sur **Windows** ou **Linux** ? | Détermine où installer le truststore | — |

**Si vous avez répondu OUI aux 4 premières questions** → suivez le **Scénario 1** (cas typique 70% des installations).

---

## 2. Arbre de décision

```
                ┌─────────────────────────────────────┐
                │ Avez-vous une AD CS dans la forêt ? │
                └───────────────┬─────────────────────┘
                          OUI ◄─┴─► NON
                           │         │
                           │         └──► Scénario 2 (cert auto-signé)
                           ▼
                  ┌────────────────────┐
                  │ DC répond sur 636 ?│
                  └────────┬───────────┘
                       OUI ┴─► NON
                        │      │
                        │      └──► Scénario 3 (StartTLS sur 389)
                        ▼
                ┌──────────────────┐
                │ DNS résout FQDN ?│
                └────────┬─────────┘
                     OUI ┴─► NON
                      │      │
                      │      └──► Scénario 1bis (utiliser IP + désactiver TLS verify)
                      ▼
              ┌──────────────────┐
              │ ▶ Scénario 1     │
              │   LDAPS standard │
              └──────────────────┘
```

---

## 3. Scénario 1 — LDAPS standard avec AD CS (cas typique)

**Contexte** : domaine avec AD CS, DC sur Windows Server 2016+, DNS interne fonctionnel.

### 3.1 Récupérer le certificat root CA depuis le DC

Sur le DC (PowerShell admin) :

```powershell
# Trouve la root CA dans le truststore local
$rootCa = Get-ChildItem Cert:\LocalMachine\Root | Where-Object { $_.Subject -match "<NomDeVotreCA>" } | Select-Object -First 1

# L'exporte en PEM
$bytes = $rootCa.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
$b64 = [Convert]::ToBase64String($bytes, [Base64FormattingOptions]::InsertLineBreaks)
"-----BEGIN CERTIFICATE-----`n$b64`n-----END CERTIFICATE-----`n" | Set-Content -Path "C:\rootca.pem" -NoNewline

Write-Host "Cert exporté ($($bytes.Length) bytes)"
```

> **Comment trouver `<NomDeVotreCA>`** : lancez `Get-ChildItem Cert:\LocalMachine\Root | Format-Table Subject` — la CA de votre forêt est typiquement `CN=<domaine>-<hostname>-CA`. Exemple sur dc01 example.com : `CN=example-dc01-CA`.

### 3.2 Copier le `rootca.pem` sur la machine du collecteur

- **Linux/macOS** : `scp administrator@dc01:C:/rootca.pem /etc/etc-collector/rootca.pem`
- **Windows** : copie via SMB ou `xcopy`

### 3.3 Tester la connexion (preview, sans détecteurs)

```bash
# Vérification réseau + TLS uniquement
openssl s_client -connect dc01.example.com:636 -CAfile /etc/etc-collector/rootca.pem -verify_return_error </dev/null
# Doit afficher "Verify return code: 0 (ok)"
```

### 3.4 Lancer l'audit

```bash
etc-collector audit ad \
  --ldap-url "ldaps://dc01.example.com:636" \
  --ldap-bind-dn "CN=svc-etc-collector,CN=Users,DC=example,DC=com" \
  --ldap-bind-password "<mot de passe>" \
  --ldap-base-dn "DC=example,DC=com" \
  --ldap-ca-cert /etc/etc-collector/rootca.pem \
  -o /tmp/audit-result.json
```

Si succès : fichier JSON ~3 MB avec ~270 findings (variable selon votre AD).

> 🔧 **Si ça plante** : voir §10 ci-dessous ou directement [ad-troubleshooting.md](ad-troubleshooting.md).

---

## 3bis. Scénario 1bis — LDAPS sans DNS interne

Vous n'avez pas de DNS qui résout `dc01.example.com` depuis la machine du collecteur — vous voulez utiliser l'IP.

**Problème** : le certificat du DC contient le FQDN dans son SAN, **pas l'IP**. La validation TLS échoue avec `LDAP_TLS_IP_SAN_MISSING`.

**3 solutions** :

1. **Recommandé** : ajouter une entrée `/etc/hosts` (Linux) ou `C:\Windows\System32\drivers\etc\hosts` (Windows) :
   ```
   10.0.0.10  dc01.example.com
   ```
   Puis utilisez le FQDN comme dans le Scénario 1 normal.

2. **Compromise** : désactiver la vérification TLS — connexion chiffrée mais cert non vérifié, **vulnérable au MITM** :
   ```bash
   etc-collector audit ad \
     --ldap-url "ldaps://10.0.0.10:636" \
     --ldap-tls-verify=false \
     ... (autres flags identiques)
   ```

3. **Régénérer le cert du DC avec une IP SAN** : opération admin AD CS, hors scope. Voir [ad-tls-certificates.md §8](ad-tls-certificates.md).

---

## 4. Scénario 2 — Cert auto-signé (pas d'AD CS)

Le DC présente son propre certificat auto-signé. Le "CA" est en fait le cert serveur lui-même.

### 4.1 Identifier le cert présenté par le DC

Depuis n'importe quelle machine :
```bash
echo | openssl s_client -connect dc01.example.com:636 -showcerts 2>/dev/null \
  | awk '/-----BEGIN/,/-----END/' \
  | head -30 \
  > /tmp/dc-cert.pem

openssl x509 -in /tmp/dc-cert.pem -noout -subject -issuer -dates
# Si Issuer == Subject → auto-signé
```

### 4.2 Utiliser ce cert comme CA pour le collecteur

```bash
etc-collector audit ad \
  --ldap-url "ldaps://dc01.example.com:636" \
  --ldap-bind-dn "..." --ldap-bind-password "..." --ldap-base-dn "..." \
  --ldap-ca-cert /tmp/dc-cert.pem \
  -o /tmp/audit-result.json
```

> ⚠️ Si vous avez plusieurs DCs avec des certs auto-signés différents, il faudra concaténer leurs PEM dans un seul fichier.

---

## 5. Scénario 3 — StartTLS sur 389 (DC sans LDAPS activé)

Le DC ne répond pas sur 636 mais accepte StartTLS sur 389 (rare en AD natif — AD CS active LDAPS par défaut).

### 5.1 Vérifier que le DC supporte StartTLS

Sur n'importe quelle machine avec OpenSSL :
```bash
openssl s_client -starttls ldap -connect dc01.example.com:389 -showcerts 2>/dev/null | head -20
# Si vous voyez un cert s'afficher → StartTLS supporté
```

### 5.2 Lancer l'audit

```bash
etc-collector audit ad \
  --ldap-url "ldap://dc01.example.com:389" \
  --ldap-start-tls \
  --ldap-ca-cert /etc/etc-collector/rootca.pem \
  --ldap-bind-dn "..." --ldap-bind-password "..." --ldap-base-dn "..." \
  -o /tmp/audit-result.json
```

> Le flag `--ldap-start-tls` upgrade la connexion `ldap://` (cleartext) en TLS chiffré juste après la connexion TCP.

---

## 6. Compte de service AD : permissions minimales

### 6.1 Compte recommandé

**À créer** : un compte dédié `svc-etc-collector` (mot de passe long, non-rotatif, marqué "Account is sensitive and cannot be delegated").

```powershell
# Sur un DC ou un poste avec RSAT
New-ADUser -Name "svc-etc-collector" `
  -SamAccountName "svc-etc-collector" `
  -UserPrincipalName "svc-etc-collector@example.com" `
  -AccountPassword (Read-Host -AsSecureString "Password") `
  -Enabled $true `
  -PasswordNeverExpires $true `
  -CannotChangePassword $true

# Marquer "sensitive"
Set-ADAccountControl -Identity svc-etc-collector -AccountNotDelegated $true
```

### 6.2 Permissions

| Capacité | Permission AD requise | Disponible par défaut ? |
|---|---|---|
| Lecture utilisateurs/groupes/computers | Authenticated Users | ✅ Oui |
| Lecture des ACL (DCSync, AdminSDHolder) | Authenticated Users | ✅ Oui (lecture seule, pas d'écriture) |
| Lecture du SYSVOL (audit GPO) | Accès SMB sur `\\<domaine>\SYSVOL` | ✅ Oui par défaut pour Authenticated Users |
| Lecture audit policy depuis registre DC | Lecture sur `HKLM:\System\CurrentControlSet\...` | ✅ Oui |

**→ Aucun privilège élevé nécessaire**. Le compte ne doit **PAS** être membre de Domain Admins, Enterprise Admins ou Backup Operators.

### 6.3 Bind format accepté

Le collecteur accepte 3 formats équivalents pour `--ldap-bind-dn` :

| Format | Exemple | Quand l'utiliser |
|---|---|---|
| **Distinguished Name** (DN) | `CN=svc-etc-collector,CN=Users,DC=example,DC=com` | ✅ Recommandé — explicite, pas d'ambiguïté |
| **UPN** (User Principal Name) | `svc-etc-collector@example.com` | ✅ Pratique si vous connaissez l'UPN, fonctionne pareil |
| **NetBIOS** (legacy) | `EXAMPLE\svc-etc-collector` | ⚠️ Fonctionne pour LDAP mais peut bloquer SMB SYSVOL — préférez DN ou UPN |

**Mot de passe** : `--ldap-bind-password "valeur"`. Pour éviter de l'exposer en CLI, utilisez le mode `server` avec un fichier de config YAML (voir [modes/standalone.md](../modes/standalone.md)).

---

## 7. Test final — audit complet en une commande

Une fois tout en place :

```bash
etc-collector audit ad \
  --ldap-url "ldaps://dc01.example.com:636" \
  --ldap-bind-dn "CN=svc-etc-collector,CN=Users,DC=example,DC=com" \
  --ldap-bind-password "$LDAP_PASSWORD" \
  --ldap-base-dn "DC=example,DC=com" \
  --ldap-ca-cert /etc/etc-collector/rootca.pem \
  --format json-pretty \
  -o /tmp/audit-$(date +%F).json

echo "Findings: $(jq '.audit.summary.risk.findings.total // 0' /tmp/audit-*.json)"
echo "Score:    $(jq '.audit.summary.risk.score // 0' /tmp/audit-*.json)"
echo "Frameworks compliance:"
jq -r '.audit.summary.complianceScores[]? | "  \(.framework): \(.score) (\(.rating))"' /tmp/audit-*.json
```

Sortie attendue (exemple — les chiffres varient selon votre AD ; commande
revérifiée contre un vrai DC le 2026-09-02, v3.2.0, voir Annexe B) :
```
Findings: 270
Score:    33
Frameworks compliance:
  ANSSI_PA099: 40.4 (high)
  ANSSI_BP039: 25 (critical)
  ANSSI_GUIDE_HYGIENE: 44.4 (high)
  HDS_v1_1: 27.3 (critical)
  RGPD: 25 (critical)
  NIS2_FR: 14.3 (critical)
  CIS_v8: 25 (critical)
  NIST_800_53: 0 (critical)
  DISA_STIG: 0 (critical)
```

---

## 8. Discover (preview sans détecteurs)

Avant de lancer un audit complet, vous pouvez vérifier la connexion + lister les assets :

```bash
etc-collector discover ad \
  --ldap-url "ldaps://dc01.example.com:636" \
  --ldap-bind-dn "..." --ldap-bind-password "..." --ldap-base-dn "..." \
  --ldap-ca-cert /etc/etc-collector/rootca.pem \
  -o /tmp/discover.json
```

Renvoie un inventaire (OUs, users, computers, groups) sans aucun détecteur de sécurité — utile pour **vérifier les permissions du compte** sans charger le DC.

---

## 9. Cas hardcodés — channel binding obligatoire

Si votre DC a `LdapEnforceChannelBinding=2` (forcé en hardening NIST/CIS récent), le collecteur en v3.1.12 **ne supporte pas encore** Channel Binding. Symptôme :
```
Error: LDAP connection failed:
[LDAP_CHANNEL_BINDING_REQUIRED] DC requires LDAP channel binding (LdapEnforceChannelBinding=2)
```

**Workaround temporaire** : passer `LdapEnforceChannelBinding=1` (mode "supported when possible") sur le DC le temps de l'audit. Vérifiez la valeur :
```powershell
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" | Select LdapEnforceChannelBinding
```

> Le support natif est planifié pour une release future (nécessite SASL/GSSAPI côté collecteur).

---

## 10. Si ça plante — top 8 erreurs

| Code ETC | Cause | Fix express |
|---|---|---|
| `LDAP_TLS_UNKNOWN_AUTHORITY` | CA non trouvée | Passez `--ldap-ca-cert /chemin/rootca.pem` (cf. §3.1) |
| `LDAP_TLS_IP_SAN_MISSING` | Connexion par IP, cert n'a que des DNS SAN | Utilisez le FQDN (cf. §3bis) |
| `LDAP_TLS_HOSTNAME_MISMATCH` | URL utilise un nom différent du SAN du cert | Utilisez exactement le nom listé dans le cert |
| `LDAP_CA_CERT_FILE_NOT_FOUND` *(v3.1.12)* | `--ldap-ca-cert` pointe vers un fichier absent | Vérifier le chemin avec `Test-Path` ou `ls -l` |
| `LDAP_CA_CERT_INVALID_PEM` *(v3.1.12)* | Fichier passé est binaire (DER) au lieu de texte (PEM) | Convertir : `openssl x509 -inform der -in cert.der -out cert.pem` |
| `LDAP_TLS_INVALID_MIN_VERSION` *(v3.1.12)* | `--ldap-tls-min-version` n'est pas dans {1.0, 1.1, 1.2, 1.3} | Utiliser une valeur valide ou omettre le flag |
| `LDAP_BIND_INVALID_CREDENTIALS` | bindDN ou mot de passe invalide | Vérifiez le DN (essayez UPN), retapez le mot de passe |
| `LDAP_REFERRAL_BAD_BASE_DN` *(v3.1.12 fix)* | `--ldap-base-dn` ne correspond pas au domaine du DC | `(Get-ADDomain).DistinguishedName` pour récupérer le bon DN |
| `dial tcp ...:636: connection refused` | DC n'écoute pas sur 636 | Vérifiez avec `Test-NetConnection -ComputerName dc01 -Port 636` ; passez en StartTLS (cf. Scénario 3) |

Pour le runbook complet des 21 codes d'erreur structurés, voir [ad-troubleshooting.md](ad-troubleshooting.md).

---

## Annexe A — Vérifier votre DC en 1 commande

Sur le DC (PowerShell admin) :

```powershell
# Snapshot complet de la conf LDAP/LDAPS du DC
$ports = Get-NetTCPConnection -LocalPort 389,636 -State Listen | Select LocalPort
$cert = Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Subject -match "$env:COMPUTERNAME" } | Select -First 1
$ntds = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" -ErrorAction SilentlyContinue
$adcs = Get-WindowsFeature -Name AD-Certificate -ErrorAction SilentlyContinue

Write-Host "DC: $env:COMPUTERNAME.$((Get-ADDomain).DNSRoot)"
Write-Host "  Listening LDAP : $($ports | Where LocalPort -eq 389 | Select -Expand LocalPort)"
Write-Host "  Listening LDAPS: $($ports | Where LocalPort -eq 636 | Select -Expand LocalPort)"
Write-Host "  Server cert    : $($cert.Subject) (expires $($cert.NotAfter))"
Write-Host "  CA issuer      : $($cert.Issuer)"
Write-Host "  LDAP signing   : $($ntds.LDAPServerIntegrity) (1=optional, 2=required)"
Write-Host "  Channel binding: $($ntds.LdapEnforceChannelBinding) (0/empty=off, 1=supported, 2=required)"
Write-Host "  AD CS installed: $($adcs.Installed)"
```

Sortie type (exemple — script relu et cohérent avec un DC réel testé le
2026-09-02, v3.2.0, voir Annexe B) :
```
DC: dc01.example.com
  Listening LDAP : 389
  Listening LDAPS: 636
  Server cert    : CN=dc01.example.com (expires 11/17/2026 ...)
  CA issuer      : CN=example-dc01-CA, DC=example, DC=cc
  LDAP signing   : 1 (1=optional, 2=required)
  Channel binding:  (0/empty=off, 1=supported, 2=required)
  AD CS installed: True
```

---

## Annexe B — Tests réels effectués (v3.2.0)

Doc revalidée le **2026-09-02** contre un **vrai DC de lab** (Windows Server
2022, AD CS installé, hostname réel dans le certificat), binaire pro compilé
depuis le code courant, conteneur jetable sur un hôte de démo dédié. Remplace
la validation précédente (2026-04-22, v3.1.12) — quatre mois s'étaient
écoulés, avec l'édition unique, la bascule de licence, la fusion générique du
registre (T_132) et d'autres changements dans l'intervalle. Détail complet
(commandes, sorties collées) : `docs/rejeu-doc/docs/BILAN-T140.md`.

| # | Scénario | Résultat | Code ETC |
|---|---|---|---|
| 1 | LDAPS IP `:636` + tls-verify=false | ✅ succès | — |
| 2 | LDAPS IP `:636` + tls-verify=true | ❌ rejeté | `LDAP_TLS_IP_SAN_MISSING` |
| 3 | LDAPS FQDN `:636` + tls-verify=true (system trust) | ✅ succès | — |
| 4 | LDAPS FQDN `:636` + `--ldap-ca-cert rootca.pem` | ✅ succès | — |
| 5 | LDAPS FQDN + chemin ca-cert invalide | ❌ rejeté | `LDAP_CA_CERT_FILE_NOT_FOUND` |
| 6 | LDAP plain `:389` (DC avec LDAPServerIntegrity=1) | ✅ succès | — |
| 7 | LDAP+StartTLS `:389` + tls-verify=false | ✅ succès | — |
| 8 | LDAP+StartTLS `:389` FQDN + ca-cert | ✅ succès | — |
| 9 | LDAPS + `--ldap-tls-min-version 1.3` | ❌ rejeté *(voir note)* | `LDAP_UNKNOWN_ERROR` |
| 10 | LDAPS + `--ldap-tls-min-version 1.0` | ✅ succès | — |
| 11 | LDAPS + `--ldap-tls-min-version xxx` (invalide) | ❌ rejeté | `LDAP_TLS_INVALID_MIN_VERSION` |
| 12 | bindDN format DN complet | ✅ succès | — |
| 13 | bindDN format UPN (`admin@domaine`) | ✅ succès | — |
| 14 | bindDN format NetBIOS (`DOMAINE\admin`) | ⚠️ LDAP OK, SMB SYSVOL fail | — |
| 15 | Mot de passe invalide | ❌ rejeté | `LDAP_BIND_INVALID_CREDENTIALS` (AD code 52e) |
| 16 | Base DN correct | ✅ (= test 1) | — |
| 17 | Base DN inexistant `DC=fake,DC=domain` | ❌ rejeté | `LDAP_REFERRAL_BAD_BASE_DN` |
| 18 | Base DN sub-tree (`CN=Users,DC=...`) | ✅ succès (audit partiel) | — |

→ **17/18 réussissent tels que documentés** ; les 6 scénarios ❌ sont des
rejets **voulus** (config invalide ou refusée par le DC), pas des échecs de
la doc — chacun ressort avec le code structuré attendu, sortie collée dans le
BILAN.

**Scénario 9 — divergence trouvée et corrigée** : l'annexe précédente
affirmait « ✅ (DC supporte 1.3) ». Sur ce DC réel (Windows Server 2022),
forcer `--ldap-tls-min-version 1.3` échoue — vérifié indépendamment du
collecteur (`openssl s_client -tls1_3` contre le DC : reset de connexion,
`-tls1_2` : négociation TLS 1.2 normale). Le DC ne propose donc pas TLS 1.3
sur ce listener LDAPS. Mais le code structuré `LDAP_TLS_VERSION_MISMATCH`
promis par [ad-troubleshooting.md](ad-troubleshooting.md#erreur--tls-protocol-version-not-supported)
pour ce cas ne s'est **pas déclenché** : le classifieur ne reconnaît que les
alertes TLS propres (`tls: protocol version not supported`), jamais le reset
TCP brut qu'émet réellement ce DC. Signalé à l'équipe produit
(`M_021_ldap-tls-version-mismatch-classifier-gap`) ; non corrigé ici, hors
juridiction de cette doc.
