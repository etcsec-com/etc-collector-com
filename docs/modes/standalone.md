# Standalone Server Mode

The standalone mode (`etc-collector server`) runs a local REST API server and web GUI. No SaaS connection is required — everything stays on your infrastructure.

---

## Architecture

```
┌──────────────────────────────────────────────────────┐
│                  Your Network                        │
│                                                      │
│  [Web Browser / API Client]                          │
│           ↓ HTTP/HTTPS :8443                         │
│  ┌─────────────────────────────┐                     │
│  │   etc-collector server      │                     │
│  │   ├── REST API (/api/v1)    │                     │
│  │   ├── Web GUI (Alpine.js)   │                     │
│  │   └── Audit Engine          │                     │
│  └────────────┬────────────────┘                     │
│               ↓ LDAP/LDAPS :636                      │
│  [Active Directory Domain Controllers]               │
│               ↓ SMB :445                             │
│  [SYSVOL / GPO Files]                                │
│               ↓ HTTPS :443                           │
│  [Microsoft Graph API] (if Azure configured)         │
└──────────────────────────────────────────────────────┘
```

---

## Starting the Server

### With a config file

```bash
# Using /etc/etc-collector/config.yaml (system install)
etc-collector server

# Using a specific config file
etc-collector server --config /path/to/config.yaml

# Using default ./config.yaml in current directory
etc-collector server
```

### With command-line flags

```bash
etc-collector server \
  --port 8443 \
  --ldap-url ldaps://dc.example.com:636 \
  --ldap-bind-dn "CN=svc-audit,CN=Users,DC=example,DC=com" \
  --ldap-bind-password "P@ssw0rd" \
  --ldap-base-dn "DC=example,DC=com"
```

### With self-signed certificate (skip TLS verify)

```bash
etc-collector server \
  --ldap-url ldaps://dc.example.com:636 \
  --ldap-bind-dn "CN=svc-audit,CN=Users,DC=example,DC=com" \
  --ldap-bind-password "P@ssw0rd" \
  --ldap-base-dn "DC=example,DC=com" \
  --ldap-tls-verify=false
```

### With network probes enabled

```bash
etc-collector server \
  --ldap-url ldaps://dc.example.com:636 \
  --ldap-bind-dn "CN=svc-audit,CN=Users,DC=example,DC=com" \
  --ldap-bind-password "P@ssw0rd" \
  --ldap-base-dn "DC=example,DC=com" \
  --enable-network-probes
```

---

## Web GUI

Once the server is running, open your browser:

```
http://localhost:8443
```

> **`http://` above is only correct for the default `--host 127.0.0.1`.**
> `etc-collector server` (and `server enable`) accept a `--host` flag; the
> moment it's set to anything non-loopback (`0.0.0.0`, a LAN IP, ...), TLS
> becomes mandatory. If `server.tlsCertFile`/`tlsKeyFile` aren't configured, a
> bootstrap self-signed certificate is generated automatically and the GUI
> serves **`https://`** instead (browsers will warn — it isn't signed by a
> public CA). Pass `--allow-insecure-http` to force plain `http://` on a
> non-loopback host instead; every request served that way is logged.
> Confirmed live (disposable container, v3.2.0, 2026-09-02): `etc-collector
> server --host 0.0.0.0 --port 8443` logs `Admin server is bound to a
> non-loopback interface with no certificate configured — generated a
> bootstrap self-signed one`; `curl http://127.0.0.1:8443/health` then
> returns `400 Client sent an HTTP request to an HTTPS server`, while `curl -k
> https://127.0.0.1:8443/health` returns `200 {"status":"ok",...}`.

The GUI provides:
- **Dashboard** — Risk score, finding summary by severity, top findings
- **Audit** — Launch a new audit, view progress, download results
- **Configuration** — Update LDAP/Azure settings without restarting
- **Jobs** — View past audit runs and their results

### GUI Access Token

The GUI is protected by an access token generated at install time:

```bash
# View or reset the GUI token
etc-collector gui-token reset
```

The token is shown **once** and stored only as a SHA-256 hash. If lost, reset it with the command above (requires service restart).

---

## REST API

The same server exposes a full REST API at `/api/v1`. See the [API Reference](../API.md).

### Create a JWT for automation

```bash
# Using the GUI token to create a long-lived JWT
curl -X POST http://localhost:8443/api/v1/auth/token \
  -H "Content-Type: application/json" \
  -H "X-GUI-Token: etcsec_gt_..." \
  -d '{"service":"automation","duration":"30d"}'
```

---

## Typical Use Cases

### 1. One-time Audit with GUI

Start the server, open the GUI, run an audit, export the results, stop the server.

```bash
etc-collector server \
  --ldap-url ldaps://dc.example.com:636 \
  --ldap-bind-dn "CN=svc-audit,CN=Users,DC=example,DC=com" \
  --ldap-bind-password "P@ssw0rd" \
  --ldap-base-dn "DC=example,DC=com"
```

### 2. Persistent API for SIEM Integration

Deploy as a service on a dedicated VM. Configure your SIEM to call `POST /api/v1/audit/ad` periodically and push results.

### 3. CI/CD Pipeline

```yaml
# GitHub Actions example
- name: Run AD audit
  run: |
    etc-collector server --config config.yaml &
    sleep 5
    TOKEN=$(curl -s -X POST http://localhost:8443/api/v1/auth/token \
      -H "X-GUI-Token: $GUI_TOKEN" \
      -d '{"service":"ci","duration":"1h"}' | jq -r .token)
    curl -s -X POST http://localhost:8443/api/v1/audit/ad \
      -H "Authorization: Bearer $TOKEN" \
      -d '{"includeDetails":false}' > audit-results.json
```

### 4. Offline / Air-Gapped Environments

With no internet access needed, the collector only communicates with:
- Your Domain Controllers (LDAP/LDAPS, SMB)
- Microsoft Graph (only if Azure configured)

---

## Configuration

All configuration can be set via:
1. Config file (`config.yaml`)
2. Environment variables
3. CLI flags

See [Configuration Reference](../configuration/README.md) for the full config file documentation.

---

## Stopping the Server

```bash
# If running in foreground
Ctrl+C

# If running as a service
sudo systemctl stop etcsec-collector    # Linux
sudo launchctl unload ...               # macOS
net stop "ETCSec"                       # Windows
```
