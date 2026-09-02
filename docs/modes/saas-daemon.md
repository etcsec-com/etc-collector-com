# SaaS Daemon Mode

In daemon mode (`etc-collector daemon`), the collector runs as a persistent background service that polls the SaaS platform at `api.etcsec.com` for commands, executes audits, and reports results remotely. An optional local GUI/API server can run alongside.

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│  CLOUD                                                           │
│  ┌──────────────────────────────┐                                │
│  │   SaaS Platform              │                                │
│  │   api.etcsec.com             │ ← Operator manages from here  │
│  └──────────────┬───────────────┘                                │
│                 ↕ HTTPS (polling every N seconds)               │
├──────────────────────────────────────────────────────────────────┤
│  ON-PREMISES / CUSTOMER SITE                                     │
│  ┌────────────────────────────────────────────────┐             │
│  │   etc-collector daemon                         │             │
│  │   ├── SaaS poll loop (receive commands)        │             │
│  │   ├── Audit engine                             │             │
│  │   ├── Health reporter                          │             │
│  │   ├── Auto-updater (binary update watcher)     │             │
│  │   └── Local GUI/API server (optional :8443)    │             │
│  └──────────┬─────────────────┬───────────────────┘             │
│             ↓ LDAP :636       ↓ Graph API :443                  │
│  [Active Directory]   [Azure Entra ID / Microsoft]              │
└──────────────────────────────────────────────────────────────────┘
```

---

## Setup Workflow

### Step 1: Enroll the Collector

Enrollment registers this instance with the SaaS platform and stores encrypted credentials locally.

```bash
read -rsp 'Enrollment token: ' ETCSEC_ENROLL_TOKEN && echo
export ETCSEC_ENROLL_TOKEN ETCSEC_SAAS_URL=https://api.etcsec.com

etc-collector enroll

unset ETCSEC_ENROLL_TOKEN
```

The prompt keeps the token out of the command line — a token typed as an
argument is visible in `ps` to any local user while the command runs, and stays
in your shell history afterwards. Passing it as an argument
(`etc-collector enroll TOKEN`) is still supported.

The token is sent as a field of a JSON POST body over HTTPS, never in a URL. It
is never written into the systemd unit or the Windows service definition, never
persisted to `credentials.json`, and never logged.

The enrollment token is obtained from the SaaS platform dashboard when creating a new collector.

After enrollment, a credentials file is saved to the config directory (encrypted). The plaintext token is not stored.

### Step 2: Start the Daemon

```bash
# Start in foreground (for testing)
etc-collector daemon

# As a systemd service (production)
sudo systemctl start etcsec-collector
```

### Step 3: Verify

```bash
etc-collector status
```

Output:
```
Status:       Enrolled
Collector ID: 550e8400-e29b-41d4-a716-446655440000
SaaS URL:     https://api.etcsec.com
LDAP:         ldaps://dc.example.com:636 (configured)
Azure:        not configured
Poll interval: 30s
Credentials:  /etc/etc-collector/credentials.json
```

---

## How the Daemon Operates

1. **Polling**: The daemon sends an HTTP request to `{saas-url}/api/collector/poll` every N seconds (default: 30 seconds)
2. **Command processing**: The platform responds with a command (e.g., `RUN_AUDIT`, `UPDATE_CONFIG`, `RESTART`)
3. **Execution**: The daemon runs the requested audit using the locally-configured providers
4. **Reporting**: Results are sent back to the SaaS platform
5. **Health reporting**: The daemon periodically reports uptime, version, and provider status

---

## Local GUI in Daemon Mode

The local GUI is **disabled on network interfaces by default** in daemon mode (only `127.0.0.1`). This is intentional — the collector sits inside the customer network and the GUI is not always needed.

### Enable the GUI

```bash
# Accessible from the local machine only
etc-collector server enable --host 127.0.0.1 --port 8443

# Accessible from the network (internal)
etc-collector server enable --host 0.0.0.0 --port 8443

# Without interactive prompts (scripted)
etc-collector server enable --host 0.0.0.0 --port 8443 --yes
```

> **A non-loopback `--host` (`0.0.0.0` above, or `--gui-host 0.0.0.0` on
> `daemon`) forces TLS.** If no certificate is configured, a bootstrap
> self-signed one is generated automatically and the GUI switches from
> `http://` to **`https://`** (browsers will warn — not a public CA). Pass
> `--allow-insecure-http` (`--gui-allow-insecure-http` on `daemon`) to force
> plain HTTP instead; every request served that way is logged. `--host
> 127.0.0.1` above stays plain `http://` — only the non-loopback case changes
> scheme.

### Disable the GUI

```bash
etc-collector server disable
```

The SaaS daemon continues polling — only the local GUI is affected.

---

## LDAP/Azure Configuration

In daemon mode, LDAP and Azure configuration can come from:

1. **SaaS platform** — pushed as an `UPDATE_CONFIG` command (stored encrypted locally)
2. **Local config file** — `/etc/etc-collector/config.yaml`
3. **CLI flags** — override at startup

```bash
# Override LDAP from daemon CLI flags
etc-collector daemon \
  --ldap-url ldaps://dc.example.com:636 \
  --ldap-bind-dn "CN=svc-audit,CN=Users,DC=example,DC=com" \
  --ldap-bind-password "P@ssw0rd" \
  --ldap-base-dn "DC=example,DC=com"
```

---

## Automatic Binary Updates

In daemon mode, the collector can update itself when a new version is pushed from the SaaS platform:

1. SaaS sends an `UPDATE_BINARY` command with download URL + checksum
2. Daemon downloads the new binary to a staging directory
3. A watcher subprocess (`update watch`) takes over: waits for the parent to exit
4. Parent exits
5. Watcher replaces the binary and restarts the service
6. On Linux: `restorecon` is called automatically if SELinux is detected

---

## Multi-Site Deployment

The daemon is designed for deploying one collector per AD site/domain:

```
SaaS Platform
├── Site A — Collector (daemon on server-a.contoso.com)
│   └── contoso.com AD domain
├── Site B — Collector (daemon on server-b.fabrikam.local)
│   └── fabrikam.local AD domain
└── Azure — Collector (daemon on azure-collector.example.com)
    └── Azure Entra ID tenant
```

Each collector is enrolled independently and managed from the SaaS dashboard.

---

## Unenroll

```bash
etc-collector unenroll
```

This:
1. Notifies the SaaS platform (best-effort)
2. Deletes local credentials
3. The daemon will fail at next startup (not enrolled)

---

## Daemon Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--config-dir` | `/etc/etc-collector` | Directory containing `credentials.json` |
| `--ldap-url` | (from SaaS config) | Override LDAP URL |
| `--ldap-bind-dn` | (from SaaS config) | Override LDAP bind DN |
| `--ldap-bind-password` | (from SaaS config) | Override LDAP password |
| `--ldap-base-dn` | (from SaaS config) | Override base DN |
| `--ldap-tls-verify` | `true` | Override TLS verification |
| `--gui-port` | `8443` | Local GUI port (`0` = disabled) |
| `--gui-host` | `127.0.0.1` | Local GUI listen address |
