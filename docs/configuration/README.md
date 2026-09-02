# Configuration

ETC Collector can be configured via a YAML file, environment variables, or CLI flags.

**Priority order (highest to lowest):** CLI flags > environment variables >
`config.yaml` > built-in defaults (first non-empty source wins; a duration of
`0` counts as "not set"). See `internal/config/precedence.go` for the
authoritative implementation.

This does not apply to SaaS-enrolled daemons (`etc-collector daemon`): a
collector enrolled with the cloud receives its provider configuration through
commands and stores it in `credentials.json`. It never reads `config.yaml` for
those settings, and `config.yaml` never reaches the daemon's provider setup —
the two modes are independent by construction.

---

## Config File Location

The server searches for `config.yaml` in this order:
1. `./config.yaml` (current working directory)
2. `~/.etc-collector/config.yaml` (user config)
3. `/etc/etc-collector/config.yaml` (system config)

Override with `--config /path/to/config.yaml`.

---

## Full Configuration Reference

```yaml
# ─── Server ──────────────────────────────────────────────────────────────────
server:
  host: "0.0.0.0"       # Listen address. "127.0.0.1" for local-only access
  port: 8443             # API and GUI port

# ─── LDAP / Active Directory ─────────────────────────────────────────────────
ldap:
  url: "ldaps://dc.example.com:636"
  # Supported schemes:
  #   ldap://   port 389 (cleartext — not recommended in production)
  #   ldaps://  port 636 (TLS — recommended)
  #   ldap://   port 389 with startTLS: true (upgrade to TLS)

  bindDN: "CN=svc-audit,CN=Users,DC=example,DC=com"
  # Distinguished Name of the service account used for LDAP bind.
  # Minimum permissions: Domain Users (read-only on all objects).

  bindPassword: "${LDAP_BIND_PASSWORD}"
  # Supports ${ENV_VAR} substitution in the value.
  # Never commit plaintext passwords — use env vars or a secrets manager.

  baseDN: "DC=example,DC=com"
  # Base distinguished name for all LDAP searches.
  # Typically the domain root: DC=example,DC=com

  tlsVerify: true
  # true  → Verify DC TLS certificate against trusted CAs (recommended)
  # false → Skip TLS verification (use only with self-signed certs in lab)

  timeout: 30s
  # LDAP connection and operation timeout.

  pageSize: 1000
  # LDAP paging: number of entries returned per request.
  # Lower for DCs with strict per-request limits.
  # ⚠️ Currently parsed and displayed only — not yet consumed by the LDAP
  # provider to page results. Setting it has no effect today.

# ─── Azure Entra ID ──────────────────────────────────────────────────────────
azure:
  tenantId: ""
  # Azure AD tenant ID (GUID format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)

  clientId: ""
  # App registration client ID

  clientSecret: "${AZURE_CLIENT_SECRET}"
  # App registration client secret.
  # Required permissions: see docs/configuration/permissions.md#azure-entra-id

  # Certificate auth — alternative to clientSecret, and the only option in
  # tenants that forbid client secrets. A configured certificate wins if both
  # are set. See permissions.md#certificate-authentication-recommended.
  # clientCertPath: "/etc/etc-collector/entra.pem"      # PEM bundle or .pfx/.p12
  # clientCertPem: "${AZURE_CLIENT_CERT_PEM}"           # inline PEM — no CLI flag exists for this
  # clientCertPassword: "${AZURE_CLIENT_CERT_PASSWORD}" # only for an encrypted .pfx/.p12

# ─── Authentication (JWT) ────────────────────────────────────────────────────
auth:
  jwtPrivateKeyPath: "/etc/etc-collector/keys/private.pem"
  # RSA private key (2048-bit minimum) for signing JWT tokens.
  # Generate: openssl genrsa -out private.pem 2048

  jwtPublicKeyPath: "/etc/etc-collector/keys/public.pem"
  # Corresponding RSA public key for verifying JWT tokens.
  # Generate: openssl rsa -in private.pem -pubout -out public.pem

  tokenLifetime: 720h
  # Default JWT lifetime. Format: Ns, Nm, Nh, Nd (e.g., 24h, 30d, 720h)
  # Per-token override available via POST /api/v1/auth/token
  #
  # ⚠️ Behavior change: this value is now actually applied at issuance —
  # it used to be parsed and echoed back by the admin API while every token
  # issued was hardcoded to 24h regardless. If this section is already in
  # your file (the Windows installer writes 720h by default), your tokens
  # will now last that long instead of 24h. Set it explicitly to 24h to
  # keep the previous behavior. A file with no auth: section is unaffected.

# ─── Logging ─────────────────────────────────────────────────────────────────
log:
  level: "info"
  # debug — all internal operations (verbose, use for troubleshooting)
  # info  — normal operation (default)
  # warn  — only warnings and errors
  # error — only errors

  format: "console"
  # console — human-readable with colors (for terminals)
  # json    — structured JSON lines (for log aggregators: Splunk, Elastic)

# ─── SaaS (Daemon Mode) ──────────────────────────────────────────────────────
saas:
  url: "https://api.etcsec.com"
  # SaaS backend URL. Only used in daemon mode (etc-collector daemon).
  # dataDir was removed — it was parsed but never read. The daemon's data
  # directory comes from DefaultDataDir()/ETCSEC_DATA_DIR, not config.yaml.

# ─── Features ────────────────────────────────────────────────────────────────
features:
  networkProbes: false
  # true  → Enable active network probes:
  #          - DNS zone transfer (AXFR) test
  #          - LDAP channel binding check
  #          - SMB signing check
  #          - ADCS HTTP endpoint (ESC8)
  # false → Skip network probes (default — no extra network access required)
```

---

## Minimal Configuration (AD Only)

```yaml
ldap:
  url: "ldaps://dc.example.com:636"
  bindDN: "CN=svc-audit,CN=Users,DC=example,DC=com"
  bindPassword: "YourPassword"
  baseDN: "DC=example,DC=com"
```

---

## Multi-Domain Configuration

To audit multiple domains, run separate collector instances, each with their own config:

```bash
# Domain A
etc-collector server --config /etc/etc-collector/domain-a.yaml --port 8443

# Domain B (different port)
etc-collector server --config /etc/etc-collector/domain-b.yaml --port 8444
```

---

## Secrets Management

**Never commit passwords to source control.** Recommended approaches:

### Environment variables

```bash
export LDAP_BIND_PASSWORD="YourPassword"
export AZURE_CLIENT_SECRET="YourSecret"
etc-collector server
```

### systemd drop-in

```bash
sudo systemctl edit etcsec-collector
```

```ini
[Service]
EnvironmentFile=/etc/etc-collector/secrets.env
```

`/etc/etc-collector/secrets.env`:
```
LDAP_BIND_PASSWORD=YourPassword
AZURE_CLIENT_SECRET=YourSecret
```

```bash
sudo chmod 600 /etc/etc-collector/secrets.env
sudo systemctl daemon-reload && sudo systemctl restart etcsec-collector
```

### HashiCorp Vault / AWS Secrets Manager

Use your secrets manager to inject environment variables into the process:

```bash
# Vault agent
vault agent -config=vault-agent.hcl

# AWS SSM Parameter Store
LDAP_BIND_PASSWORD=$(aws ssm get-parameter --name /etcsec/ldap-password \
  --with-decryption --query Parameter.Value --output text)
etc-collector server
```

---

## TLS Configuration

### LDAPS with self-signed certificate

```yaml
ldap:
  url: "ldaps://dc.example.com:636"
  tlsVerify: false    # Only for labs/testing
```

### LDAP with StartTLS

```yaml
ldap:
  url: "ldap://dc.example.com:389"
  tlsVerify: true
  # startTLS is detected automatically when url uses ldap:// scheme
```

---

## Active Directory — guides détaillés

- 🆕 **[ad-getting-started.md](ad-getting-started.md)** — **Démarrage rapide pour admin junior**. Arbre de décision + 5 walkthroughs orchestrés (LDAPS standard, cert auto-signé, StartTLS, plain, channel binding). Validé sur dc01 v3.1.12.
- [ad-connection-modes.md](ad-connection-modes.md) — LDAP plain vs LDAPS vs StartTLS, quand utiliser quoi
- [ad-tls-certificates.md](ad-tls-certificates.md) — extraire et installer la CA du DC (5 méthodes), conversion DER/PEM, schémas AD CS
- [ad-troubleshooting.md](ad-troubleshooting.md) — runbook : 21 codes d'erreur structurés (`LDAP_*`) avec cause / fix / lien doc

## Audit scope — choisir quels détecteurs exécuter

- [audit-scope.md](audit-scope.md) — 3 axes (catégories / IDs / profils) combinables, surface CLI / env / YAML / SaaS / trial (v3.0.22+)

## Update mechanism — UPDATE_COLLECTOR sur Unix

- [update-mechanism.md](update-mechanism.md) — exec en place sur Unix (v3.0.23+), nouveau layout binaire, **migration depuis v3.0.22 via `install --upgrade`**

## Compliance — frameworks et structure JSON (v3.1.0+)

- [compliance.md](compliance.md) — frameworks supportés (ANSSI PA-022, HDS v1.1, RGPD art.32), structure `Finding.compliance[]` + `summary.complianceScores[]`, scope profiles `compliance-anssi/hds/rgpd`

> Azure : la procédure portail est simple (App registration + 11 perms Graph), voir [permissions.md#azure-entra-id](permissions.md#azure-entra-id).

---

## See Also

- [Environment Variables](environment-variables.md) — complete variable reference
- [Permissions](permissions.md) — AD service account and Azure app setup
