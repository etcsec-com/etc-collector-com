# Environment Variables

Environment variables take precedence over the config file but are overridden by CLI flags. Not every `config.yaml` field has an environment variable — this page lists what actually exists in code.

---

## Complete Reference

### Server

| Variable | Config Equivalent | Type | Default | Description |
|----------|------------------|------|---------|-------------|
| `PORT` | `server.port` | int | `8443` | API and GUI listen port |
| `HOST` | `server.host` | string | `0.0.0.0` | Listen address |

### LDAP / Active Directory

| Variable | Config Equivalent | Type | Default | Description |
|----------|------------------|------|---------|-------------|
| `LDAP_URL` | `ldap.url` | string | — | LDAP server URL (e.g., `ldaps://dc.example.com:636`) |
| `LDAP_BIND_DN` | `ldap.bindDN` | string | — | Service account distinguished name |
| `LDAP_BIND_PASSWORD` | `ldap.bindPassword` | string | — | Service account password |
| `LDAP_BASE_DN` | `ldap.baseDN` | string | — | Base DN for LDAP searches |
| `LDAP_TLS_VERIFY` | `ldap.tlsVerify` | bool | `true` | Verify TLS certificate (`true`/`false`) |
| `LDAP_TLS_CA_CERT` | `ldap.tlsCACert` | string | — | Path to a PEM CA file (v3.0.21+) |
| `LDAP_TLS_CA_CERT_PEM` | `ldap.tlsCACertPEM` | string | — | Inline PEM CA content (v3.0.21+) |
| `LDAP_TLS_MIN_VERSION` | `ldap.tlsMinVersion` | string | — | `1.0`, `1.1`, `1.2`, `1.3` (v3.0.21+) |
| `LDAP_START_TLS` | `ldap.startTLS` | bool | `false` | Upgrade `ldap://` (389) via StartTLS (v3.0.21+) |
| `ETCSEC_LDAP_TIMEOUT` | `ldap.timeout` | duration | `30s` | LDAP connection timeout. No longer discarded after being read (previously hardcoded to 30s regardless of this value) |
| `LDAP_PAGE_SIZE` | `ldap.pageSize` | int | `1000` | ⚠️ Parsed and displayed, but not yet consumed by the LDAP provider — setting it has no effect |

### Azure Entra ID

| Variable | Config Equivalent | Type | Default | Description |
|----------|------------------|------|---------|-------------|
| `AZURE_TENANT_ID` | `azure.tenantId` | string | — | Azure AD tenant GUID |
| `AZURE_CLIENT_ID` | `azure.clientId` | string | — | App registration client ID |
| `AZURE_CLIENT_SECRET` | `azure.clientSecret` | string | — | App registration client secret |
| `AZURE_CLIENT_CERT` | `azure.clientCertPath` | string | — | Path to a client certificate (PEM bundle or `.pfx`/`.p12`) |
| `AZURE_CLIENT_CERT_PEM` | `azure.clientCertPem` | string | — | The certificate inline (multi-line PEM) — no CLI flag exists for this, only file/env |
| `AZURE_CLIENT_CERT_PASSWORD` | `azure.clientCertPassword` | string | — | Password for an encrypted `.pfx`/`.p12` bundle |

### Authentication (JWT)

| Variable | Config Equivalent | Type | Default | Description |
|----------|------------------|------|---------|-------------|
| `JWT_PRIVATE_KEY_PATH` | `auth.jwtPrivateKeyPath` | string | `./keys/private.pem` | RSA private key path |
| `JWT_PUBLIC_KEY_PATH` | `auth.jwtPublicKeyPath` | string | `./keys/public.pem` | RSA public key path |

`auth.tokenLifetime` has **no environment variable**. It is now actually
applied at token issuance — previously every issued token was hardcoded to
24h regardless of this setting. If your `config.yaml` already sets
`tokenLifetime` (the Windows installer writes `720h` by default), tokens
issued from now on last that long instead of 24h. A file with no `auth:`
section is unaffected.

### Logging

| Variable | Config Equivalent | Type | Default | Description |
|----------|------------------|------|---------|-------------|
| `ETCSEC_LOG_LEVEL` | `log.level` | string | `info` | `debug`, `info`, `warn`, `error` |
| `ETCSEC_LOG_FORMAT` | `log.format` | string | `console` | `console` or `json`. Config file `log:` section now works — the logger used to be built before the config file was read |

### Audit scope (v3.0.22+)

| Variable | Config Equivalent | Type | Default | Description |
|----------|------------------|------|---------|-------------|
| `AUDIT_PROFILE` | `audit.scope.profile` | string | — | `quick`, `compliance`, or `pentest` |
| `AUDIT_INCLUDE_CATEGORIES` | `audit.scope.includeCategories` | csv | — | Detector categories to include |
| `AUDIT_EXCLUDE_CATEGORIES` | `audit.scope.excludeCategories` | csv | — | Detector categories to exclude |
| `AUDIT_INCLUDE_DETECTORS` | `audit.scope.includeDetectors` | csv | — | Detector IDs to include |
| `AUDIT_EXCLUDE_DETECTORS` | `audit.scope.excludeDetectors` | csv | — | Detector IDs to exclude (wins) |

See [audit-scope.md](audit-scope.md) for semantics and precedence.

### Features

| Variable | Config Equivalent | Type | Default | Description |
|----------|------------------|------|---------|-------------|
| `ENABLE_NETWORK_PROBES` | `features.networkProbes` | bool | `false` | Enable active network probes |

### SaaS / Daemon Mode

| Variable | Config Equivalent | Type | Default | Description |
|----------|------------------|------|---------|-------------|
| `ETCSEC_SAAS_URL` | `saas.url` | string | `https://api.etcsec.com` | SaaS backend URL |
| `ETCSEC_ENROLL_TOKEN` | — | string | — | Enrollment token (for `enroll` command) |

---

## Usage Examples

### Shell / CLI

```bash
export LDAP_URL="ldaps://dc.example.com:636"
export LDAP_BIND_DN="CN=svc-audit,CN=Users,DC=example,DC=com"
export LDAP_BIND_PASSWORD="P@ssw0rd"
export LDAP_BASE_DN="DC=example,DC=com"

etc-collector server
```

### Docker run

```bash
docker run -d \
  -e LDAP_URL=ldaps://dc.example.com:636 \
  -e LDAP_BIND_DN="CN=svc-audit,CN=Users,DC=example,DC=com" \
  -e LDAP_BIND_PASSWORD="P@ssw0rd" \
  -e LDAP_BASE_DN="DC=example,DC=com" \
  -e AZURE_TENANT_ID="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" \
  -e AZURE_CLIENT_ID="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" \
  -e AZURE_CLIENT_SECRET="your-secret" \
  -e ETCSEC_LOG_FORMAT=json \
  -p 8443:8443 \
  ghcr.io/etcsec-com/etc-collector:latest server
```

### Docker Compose `.env` file

```env
# .env (never commit this file)
LDAP_BIND_PASSWORD=P@ssw0rd
AZURE_CLIENT_SECRET=your-secret
```

```yaml
# docker-compose.yml
services:
  collector:
    environment:
      - LDAP_URL=ldaps://dc.example.com:636
      - LDAP_BIND_DN=CN=svc-audit,CN=Users,DC=example,DC=com
      - LDAP_BIND_PASSWORD=${LDAP_BIND_PASSWORD}
      - LDAP_BASE_DN=DC=example,DC=com
      - AZURE_TENANT_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
      - AZURE_CLIENT_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
      - AZURE_CLIENT_SECRET=${AZURE_CLIENT_SECRET}
```

### systemd EnvironmentFile

```bash
# /etc/etc-collector/secrets.env
LDAP_BIND_PASSWORD=P@ssw0rd
AZURE_CLIENT_SECRET=your-secret
```

```ini
# /etc/systemd/system/etcsec-collector.service.d/override.conf
[Service]
EnvironmentFile=/etc/etc-collector/secrets.env
```

### Kubernetes Secret

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: etc-collector-secrets
type: Opaque
stringData:
  LDAP_BIND_PASSWORD: "P@ssw0rd"
  AZURE_CLIENT_SECRET: "your-secret"
---
apiVersion: apps/v1
kind: Deployment
spec:
  template:
    spec:
      containers:
        - name: collector
          envFrom:
            - secretRef:
                name: etc-collector-secrets
          env:
            - name: LDAP_URL
              value: "ldaps://dc.example.com:636"
            - name: LDAP_BIND_DN
              value: "CN=svc-audit,CN=Users,DC=example,DC=com"
            - name: LDAP_BASE_DN
              value: "DC=example,DC=com"
```

---

## Variable Substitution in Config File

Environment variables can also be referenced inside `config.yaml` using `${VAR_NAME}` syntax:

```yaml
ldap:
  url: "ldaps://dc.example.com:636"
  bindDN: "CN=svc-audit,CN=Users,DC=example,DC=com"
  bindPassword: "${LDAP_BIND_PASSWORD}"   # ← resolved at runtime
  baseDN: "DC=example,DC=com"

azure:
  clientSecret: "${AZURE_CLIENT_SECRET}"  # ← resolved at runtime
```
