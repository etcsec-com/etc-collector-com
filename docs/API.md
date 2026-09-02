# API Documentation

ETC Collector provides a REST API for programmatic security auditing.

## Base URL

```
http://localhost:8443/api/v1
```

### The scheme depends on what you bound the server to

This is the single most common way to get stuck, so it comes before everything else.

| `--host` | Scheme | Why |
|---|---|---|
| `127.0.0.1` (default) | `http://` | Loopback only; nothing leaves the machine. |
| `0.0.0.0`, or any routable address | **`https://`** | A non-loopback host **requires TLS**. If no certificate is configured, the server generates a bootstrap self-signed one at startup and serves HTTPS. |

Bound to `0.0.0.0` and calling it over `http://`, **every endpoint answers `400`** — including
the ones that work perfectly. That `400` is not your request being rejected: it is Go's HTTP
server saying *"Client sent an HTTP request to an HTTPS server"*. The API is fine; the scheme
is wrong.

```bash
# Bound to 0.0.0.0 — use https, and -k while the certificate is the self-signed bootstrap one
curl -k https://collector.example.com:8443/health
```

To serve plain HTTP on a non-loopback host anyway, pass `--allow-insecure-http`. Every request
served that way is logged, because the admin token then travels unencrypted.

## Authentication

The API uses two layers of authentication:

1. **GUI Access Token** — protects admin endpoints (config, token creation) and the web GUI
2. **JWT Token** (RS256) — protects audit and data endpoints

### GUI Access Token

The GUI access token is generated via `etc-collector gui-token reset` — but you don't have
to run that yourself first: confirmed live, 2026-09-02, a server started with no token
configured generates one automatically, prints it once to stdout, and writes it once to
`<config-dir>/gui-token.firstrun` (delete that file after copying the token — it isn't
needed for the collector to run). Only a SHA-256 hash is stored on disk long-term — the
plaintext token is shown once and never saved.

**Protected endpoints:** `POST /api/v1/auth/token`, `/api/v1/admin/*`

**How to pass the token:**

```bash
# Via header (recommended)
curl -H "X-GUI-Token: etcsec_gt_..." http://localhost:8443/api/v1/admin/config

# Via query parameter
curl http://localhost:8443/api/v1/admin/config?gui_token=etcsec_gt_...
```

**Verify a GUI token:**

**Endpoint:** `POST /api/v1/auth/gui-token/verify`

**Request:**
```json
{
  "token": "etcsec_gt_..."
}
```

**Response:**
```json
{
  "valid": true
}
```

If no GUI token is configured on the server, the response includes `"required": false` and all requests pass through.

### JWT Token (API Authentication)

The server needs an RSA key pair to sign and validate JWT tokens. **No manual step is
required** — confirmed live, 2026-09-02: on first start, if no key pair exists yet, the
server generates one itself under `<config-dir>/keys/` (`private.pem` + `public.pem`) and
loads it before accepting requests.

`<config-dir>` defaults to `/etc/etc-collector`, or whatever `--config-dir` /
`ETCSEC_CONFIG_DIR` points to — **not** a bare `./keys` relative to the current directory.
The Docker image sets `--config-dir /app`, so there the keys land at `/app/keys/`.

To supply your own key pair instead of the auto-generated one, place `private.pem` and
`public.pem` at that resolved path *before* starting the server:

```bash
mkdir -p /etc/etc-collector/keys   # or <config-dir>/keys, if you pass --config-dir
openssl genrsa -out /etc/etc-collector/keys/private.pem 2048
openssl rsa -in /etc/etc-collector/keys/private.pem -pubout -out /etc/etc-collector/keys/public.pem
```

For Docker, mount the keys directory as a volume: `-v ./keys:/app/keys:ro`

### Create Token

**Endpoint:** `POST /api/v1/auth/token`

**Authentication:** Requires GUI access token

**Request:**
```json
{
  "service": "my-integration",
  "duration": "24h"
}
```

**Response:**
```json
{
  "token": "eyJhbGciOiJSUzI1NiIs...",
  "expiresAt": "2024-01-16T10:30:00Z"
}
```

**Example:**
```bash
curl -X POST http://localhost:8443/api/v1/auth/token \
  -H "Content-Type: application/json" \
  -H "X-GUI-Token: etcsec_gt_..." \
  -d '{"service":"my-app","duration":"24h"}'
```

### Use Token

Include the token in the `Authorization` header:

```bash
curl -H "Authorization: Bearer YOUR_TOKEN" \
  http://localhost:8443/api/v1/audit/ad
```

### Validate Token

**Endpoint:** `POST /api/v1/auth/token/validate`

**Request:**
```json
{
  "token": "eyJhbGciOiJSUzI1NiIs..."
}
```

**Response:**
```json
{
  "valid": true,
  "subject": "system",
  "service": "my-app",
  "expiresAt": "2024-01-16T10:30:00Z"
}
```

### Token Info

**Endpoint:** `GET /api/v1/auth/token/info`

**Authentication:** Required

**Response:**
```json
{
  "subject": "system",
  "service": "my-app",
  "issuedAt": "2024-01-15T10:30:00Z",
  "expiresAt": "2024-01-16T10:30:00Z",
  "jti": "550e8400-e29b-41d4-a716-446655440000"
}
```

## Endpoints

### Health Check

**Endpoint:** `GET /health`

**Response** (rejouée contre un binaire construit depuis le code courant, v3.2.0, 2026-09-02):
```json
{
  "status": "ok",
  "timestamp": "2026-04-05T10:00:00Z",
  "version": "3.2.0"
}
```

> No `edition` field — removed from this response (and from `/info/capabilities`) by the
> code fix tracked as T_111: it used to echo `"pro"` on every install even though v3.2.0 is
> a single unified binary with no edition split, contradicting `LICENSING.md`. A binary
> built before that fix will still show `edition: "pro"` here; a fresh build from current
> code, confirmed live, does not.

### Admin Configuration

These endpoints require the GUI access token.

#### Get Configuration

**Endpoint:** `GET /api/v1/admin/config`

**Authentication:** GUI token required

**Response:**
```json
{
  "server": { "host": "0.0.0.0", "port": 8443 },
  "ldap": {
    "configured": true,
    "url": "ldaps://dc.example.com:636",
    "bindDN": "CN=svc-audit,CN=Users,DC=example,DC=com",
    "baseDN": "DC=example,DC=com",
    "tlsVerify": true,
    "connected": true
  },
  "azure": { "configured": false },
  "features": { "networkProbes": false },
  "auth": { "hasKeys": true, "tokenLifetime": "720h0m0s" }
}
```

> Secrets (bindPassword, clientSecret) are never returned.

#### Update LDAP Configuration

**Endpoint:** `PUT /api/v1/admin/config/ldap`

**Authentication:** GUI token required

**Request:**
```json
{
  "url": "ldaps://dc.example.com:636",
  "bindDN": "CN=svc-audit,CN=Users,DC=example,DC=com",
  "bindPassword": "P@ssw0rd",
  "baseDN": "DC=example,DC=com",
  "tlsVerify": true
}
```

> Omit `bindPassword` to keep the existing password.

**Response** (rejouée, 2026-09-02):
```json
{ "success": true, "message": "LDAP configured and connected" }
```

**Example:**
```bash
curl -X PUT http://localhost:8443/api/v1/admin/config/ldap \
  -H "Content-Type: application/json" \
  -H "X-GUI-Token: etcsec_gt_..." \
  -d '{"url":"ldaps://dc.example.com:636","bindDN":"CN=svc-audit,...","baseDN":"DC=example,DC=com"}'
```

#### Test LDAP Connection

**Endpoint:** `POST /api/v1/admin/config/ldap/test`

**Authentication:** GUI token required

**Request:**
```json
{
  "url": "ldaps://dc.example.com:636",
  "bindDN": "CN=svc-audit,CN=Users,DC=example,DC=com",
  "bindPassword": "P@ssw0rd",
  "baseDN": "DC=example,DC=com",
  "tlsVerify": true
}
```

**Response:**
```json
{ "success": true, "message": "Connection successful" }
```

Does not save the configuration — use `PUT /admin/config/ldap` to persist.

#### Remove LDAP Configuration

**Endpoint:** `DELETE /api/v1/admin/config/ldap`

**Authentication:** GUI token required

**Response:**
```json
{ "success": true, "message": "LDAP configuration removed" }
```

### Providers

**Endpoint:** `GET /api/v1/info/providers`

**Authentication:** Required

**Response:**
```json
{
  "providers": [
    {
      "type": "ldap",
      "connected": true
    }
  ]
}
```

### Capabilities

**Endpoint:** `GET /api/v1/info/capabilities`

**Authentication:** Required

**Response** (rejouée, v3.2.0, 2026-09-02 — `detectorCount` moves release to release, see `etc-collector audit list` for the current figure):
```json
{
  "detectorCount": 507,
  "features": {
    "ldap": true,
    "networkProbes": false,
    "sysvol": false,
    "import_pingcastle": true
  },
  "version": "3.2.0"
}
```

> `ldap` and `import_pingcastle` are static support flags (always `true` — the binary was
> built with that support, regardless of current configuration). `sysvol` is live state:
> whether the running audit engine actually has a SYSVOL/SMB provider connected. Rejouée
> with LDAP configured and connected via `PUT /admin/config/ldap`, `sysvol` still read
> `false` — LDAP alone doesn't establish it. No configuration path in this test session
> flipped it to `true`; treat the doc's field name as accurate but don't expect `true` from
> LDAP configuration alone.

### Import a PingCastle Report

**Endpoint:** `POST /api/v1/audit/import-pingcastle`

**Authentication:** Required

Parses a PingCastle `ad_hc_*.xml` health-check report and stores it as a **completed job**,
in the same shape a native AD audit produces — so `GET /api/v1/audit/jobs/:id` opens it like
any other result, and the GUI displays it identically.

Post the XML **as the raw request body**, not as a multipart form upload.

| | |
|---|---|
| Content-Type | `application/xml` |
| Max body size | 50 MB |

```bash
curl -X POST http://localhost:8443/api/v1/audit/import-pingcastle \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/xml" \
  --data-binary @ad_hc_example.com.xml
```

**Response** (`200`):
```json
{
  "jobId": "a1b2c3d4-...",
  "status": "completed",
  "message": "PingCastle report imported"
}
```

Then fetch the parsed result:

```bash
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8443/api/v1/audit/jobs/a1b2c3d4-...
```

**Errors** (all `400`): `empty_body` (nothing posted), `read_body_failed` (body exceeded
50 MB or the connection dropped), `parse_failed` (the XML is not a PingCastle health-check
report — the message carries the parser's reason).

### Audit Status

**Endpoint:** `GET /api/v1/audit/ad/status`

**Authentication:** Required

**Response:**
```json
{
  "status": "ready",
  "provider": "ldap"
}
```

> **Confirmed live, 2026-09-02, against a binary built from current code.** Started the
> server with no LDAP configured (`{"status":"not_configured","provider":null}`), then set
> it via `PUT /admin/config/ldap` (not via `--ldap-url` at startup): this endpoint now
> reports `{"status":"ready","provider":"ldap"}` right away, stable across repeated calls,
> not just once. Fixed in T_138: `internal/providers/manager.go`'s `Manager.Replace()` now
> sets `m.primary` on the first provider ever registered of a given type, the same rule
> `Register()` already applied — before the fix, `PUT /admin/config/ldap` (which calls
> `Replace()` first) left `m.primary` permanently empty, so this handler kept reporting
> not-ready even though `POST /audit/ad` worked.

### Run Active Directory Audit

**Endpoint:** `POST /api/v1/audit/ad`

**Authentication:** Required

**Request:**
```json
{
  "includeDetails": false,
  "async": false,
  "networkProbes": false
}
```

**Response** (rejouée contre un vrai domaine — 546 utilisateurs, 74 ordinateurs, 154
groupes, 352 OUs — 2026-09-02; l'exemple ci-dessous corrige plusieurs champs disparus ou
renommés depuis la dernière relecture de ce document):
```json
{
  "success": true,
  "provider": "ad",
  "audit": {
    "summary": {
      "objects": {
        "users": 1234,
        "users_enabled": 120,
        "users_disabled": 1114,
        "groups": 567,
        "ous": 45,
        "computers": 890
      },
      "risk": {
        "score": 72.5,
        "rating": "low",
        "findings": {
          "critical": 12,
          "high": 25,
          "medium": 38,
          "low": 12,
          "info": 9,
          "total": 96,
          "totalInstances": 143,
          "records": 87
        }
      },
      "complianceScores": [
        {
          "framework": "ANSSI_PA099",
          "score": 27.6,
          "rating": "critical",
          "controlsTotal": 95,
          "controlsPassed": 16,
          "controlsFailed": 42,
          "controlsManual": 37,
          "failedControls": [ ... ],
          "maturityAxes": [ ... ],
          "evaluatedControls": [ ... ]
        }
      ]
    },
    "accounts": {
      "status": { "findings": [...], "total": 5 },
      "privileged": { "findings": [...], "total": 3 },
      "dangerous": { "findings": [...], "total": 2 },
      "service": { "findings": [...], "total": 4 }
    },
    "computers": { "findings": [...], "total": 8 },
    "groups": { "findings": [...], "total": 6 },
    "security": {
      "passwords": { "findings": [...], "total": 10 },
      "kerberos": { "findings": [...], "total": 4 },
      "advanced": { "findings": [...], "total": 7 }
    },
    "permissions": { "findings": [...], "total": 15 },
    "adcs": { "findings": [...], "total": 3 },
    "gpoSecurity": { "findings": [...], "total": 5 },
    "trustsAnalysis": { "findings": [...], "total": 0 },
    "temporal": { "findings": [...], "total": 2 },
    "extendedConfig": { "findings": [...], "total": 1 },
    "attackGraph": {
      "domain": "contoso.local",
      "generatedAt": "2024-01-15T10:30:00Z",
      "version": "1",
      "uniqueNodes": 120,
      "targets": [ ... ],
      "paths": [ ... ],
      "stats": { ... }
    },
    "domainConfig": {
      "domainInfo": { ... },
      "passwordPolicy": { ... },
      "kerberosPolicy": { ... }
    },
    "metadata": {
      "provider": "ad",
      "domain": {
        "name": "contoso.local",
        "baseDN": "DC=contoso,DC=local",
        "ldapUrl": "ldap://dc.contoso.local:389"
      },
      "options": {
        "includeDetails": false,
        "includeComputers": true,
        "includeConfig": true
      },
      "execution": {
        "timestamp": "2024-01-15T10:30:00Z",
        "duration": "2m15s"
      }
    }
  }
}
```

> Rejouée, 2026-09-02: `audit` carries 14 top-level sections, not the 7 this example used to
> show — `adcs`, `attackGraph`, `extendedConfig`, `gpoSecurity`, `groups`, `temporal` and
> `trustsAnalysis` are real and were missing entirely. `summary.complianceScores` (one entry
> per compliance framework — ANSSI, HDS, RGPD, NIS2, CIS, NIST, DISA STIG, see
> [`docs/configuration/compliance.md`](configuration/compliance.md)) was also undocumented.
> Most category sections share the `{ "findings": [...], "total": N }` shape shown above —
> `attackGraph` is the one structural exception, described by its own field names instead.

Each finding in the category arrays has this structure:
```json
{
  "type": "PASSWD_NOTREQD",
  "severity": "critical",
  "category": "accounts",
  "title": "User does not require password",
  "description": "Users with PASSWD_NOTREQD flag set",
  "count": 3,
  "details": {
    "recommendation": "Disable the built-in Administrator account for daily use."
  },
  "affectedEntities": [
    {
      "name": "Guest",
      "type": "user",
      "details": { ... }
    }
  ]
}
```

> `affectedEntities` is only included when `includeDetails: true` in the request — confirmed
> live both ways, 2026-09-02. `details` is separate from `affectedEntities`: a small,
> detector-specific object (its keys vary by finding `type`) that's present either way — not
> documented before this pass.

**Example:**
```bash
TOKEN="your-token-here"

curl -X POST http://localhost:8443/api/v1/audit/ad \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "includeDetails": false,
    "async": false
  }'
```

### Async Audit

For long-running audits, use async mode:

**Request:**
```json
{
  "async": true
}
```

**Response** (rejouée, 2026-09-02 — an extra `message` field is real and was missing here):
```json
{
  "jobId": "550e8400-e29b-41d4-a716-446655440000",
  "status": "running",
  "message": "Audit started in background"
}
```

### List Jobs

**Endpoint:** `GET /api/v1/audit/jobs`

**Authentication:** Required

**Response** (rejouée, 2026-09-02):
```json
{
  "jobs": [
    {
      "id": "550e8400-e29b-41d4-a716-446655440000",
      "type": "ad_audit",
      "status": "completed",
      "createdAt": "2024-01-15T10:30:00Z",
      "completedAt": "2024-01-15T10:35:23Z"
    }
  ]
}
```

> `type` is `"ad_audit"` (a PingCastle import job shows `"pingcastle_import"`), not `"ad"` as
> this example used to show.

### Get Job

**Endpoint:** `GET /api/v1/audit/jobs/:id`

**Authentication:** Required

**Example:**
```bash
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8443/api/v1/audit/jobs/550e8400-e29b-41d4-a716-446655440000
```

**Response** (rejouée, 2026-09-02):
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "type": "ad_audit",
  "status": "completed",
  "createdAt": "2024-01-15T10:30:00Z",
  "completedAt": "2024-01-15T10:35:23Z",
  "result": { ... }
}
```

> **Confirmed live, 2026-09-02, against a binary built from current code, on a real job run
> against a live domain.** `GET /audit/jobs` (list, above) no longer returns `result` at all
> for any job; only this endpoint does, in the enveloped `{ "success", "provider", "audit" }`
> shape shown above — the same envelope `POST /audit/ad` returns. Fixed in T_138: the list
> used to serialize `result` in a second, flatter shape for the *same* job (`timestamp`,
> `duration`, `score`, `rating`, `provider`, `domain`, `domainInfo`, `findings`, ...) — a
> genuine schema divergence on one `jobId`, not a subset or superset. The embedded GUI never
> read `result` from the list, so dropping it there closed the divergence without any GUI
> change. If you need `result`, fetch it from this endpoint, not from the list.

Job statuses: `pending`, `running`, `completed`, `failed`.

## Error Handling

**Error Response Format:**
```json
{
  "error": "error_code",
  "message": "Human-readable error description"
}
```

**HTTP Status Codes:**
- `200` - Success
- `201` - Created
- `202` - Accepted (async job started)
- `400` - Bad Request
- `401` - Unauthorized
- `404` - Not Found
- `500` - Internal Server Error
- `503` - Service Unavailable

## Code Examples

### Python

```python
import requests

# Create token
response = requests.post(
    "http://localhost:8443/api/v1/auth/token",
    json={"service": "python-client", "duration": "24h"}
)
token = response.json()["token"]

# Run audit
headers = {"Authorization": f"Bearer {token}"}
response = requests.post(
    "http://localhost:8443/api/v1/audit/ad",
    headers=headers,
    json={"async": False}
)

result = response.json()
risk = result["audit"]["summary"]["risk"]
print(f"Score: {risk['score']} ({risk['rating']})")
print(f"Findings: {risk['findings']['total']}")
```

### JavaScript

```javascript
const axios = require('axios');

async function runAudit() {
  // Create token
  const tokenResponse = await axios.post(
    'http://localhost:8443/api/v1/auth/token',
    { service: 'nodejs-client', duration: '24h' }
  );
  const token = tokenResponse.data.token;

  // Run audit
  const auditResponse = await axios.post(
    'http://localhost:8443/api/v1/audit/ad',
    { async: false },
    { headers: { Authorization: `Bearer ${token}` } }
  );

  const risk = auditResponse.data.audit.summary.risk;
  console.log(`Score: ${risk.score} (${risk.rating})`);
  console.log(`Findings: ${risk.findings.total}`);
}

runAudit();
```

### PowerShell

```powershell
# Create token
$tokenBody = @{
    service = "powershell-client"
    duration = "24h"
} | ConvertTo-Json

$tokenResponse = Invoke-RestMethod -Uri "http://localhost:8443/api/v1/auth/token" `
    -Method Post -Body $tokenBody -ContentType "application/json"

$token = $tokenResponse.token

# Run audit
$headers = @{
    "Authorization" = "Bearer $token"
    "Content-Type" = "application/json"
}

$auditBody = @{ async = $false } | ConvertTo-Json

$result = Invoke-RestMethod -Uri "http://localhost:8443/api/v1/audit/ad" `
    -Method Post -Headers $headers -Body $auditBody

$risk = $result.audit.summary.risk
Write-Host "Score: $($risk.score) ($($risk.rating))"
Write-Host "Findings: $($risk.findings.total)"
```

## Finding Severity Levels

| Severity | Score | Description |
|----------|-------|-------------|
| Critical | 9.0-10.0 | Immediate exploitation possible |
| High | 7.0-8.9 | Significant security weakness |
| Medium | 4.0-6.9 | Configuration issues |
| Low | 1.0-3.9 | Minor issues |
| Info | 0.0 | Informational only |

## Best Practices

1. **Token Security**:
   - Store tokens securely (environment variables, secret managers)
   - Use short expiration times for automated scripts
   - Rotate tokens regularly

2. **Async Mode**:
   - Use async mode for large domains (>10,000 objects)
   - Poll job status every 5-10 seconds
   - Implement timeout (5-10 minutes)

3. **Error Handling**:
   - Check HTTP status codes
   - Implement retry logic with exponential backoff
   - Log errors with sufficient context

4. **Performance**:
   - Use `includeDetails: false` unless full data is needed
   - Run audits during off-peak hours
   - Consider caching results

## Support

For full documentation including installation guides and vulnerability catalog:
- [README.md](../README.md) — CLI reference, install, configuration
- [docs/vulnerabilities/](vulnerabilities/README.md) — Vulnerability catalogs
- GitHub: https://github.com/etcsec-com/etc-collector-com
