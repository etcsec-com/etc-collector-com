# Operating Modes

ETC Collector supports two distinct operating modes. Choose the one that fits your deployment context.

---

## Overview

```
┌─────────────────────────────────────────────────────────────────┐
│  STANDALONE MODE          │  SAAS DAEMON MODE                   │
│  (etc-collector server)   │  (etc-collector daemon)             │
├───────────────────────────┼─────────────────────────────────────┤
│  [Browser / API Client]   │  [SaaS Platform api.etcsec.com]     │
│         ↓ :8443           │         ↕ HTTPS polling             │
│  [etc-collector server]   │  [etc-collector daemon]             │
│         ↓ LDAP/LDAPS      │    ↓ LDAP/LDAPS  ↓ :8443 (opt.)    │
│  [Active Directory DC]    │  [AD Domain]   [Admin Browser]      │
└───────────────────────────┴─────────────────────────────────────┘
```

---

## Comparison

| Feature | Standalone | SaaS Daemon |
|---------|-----------|-------------|
| **Cloud dependency** | None — fully local | Requires `api.etcsec.com` |
| **Configuration** | Local `config.yaml` | Pushed from SaaS platform |
| **Audit trigger** | Manual (GUI or API) | Remote command via SaaS |
| **Results storage** | Local | Sent to SaaS + local |
| **GUI access** | Always on (port 8443) | Optional (disabled by default) |
| **Multi-site management** | Per-instance | Centralized from SaaS |
| **Auto-updates** | Manual | Supported (binary update via watcher) |
| **Enrollment required** | No | Yes (`etc-collector enroll`) |
| **Ideal for** | Audits ponctuels, CI/CD, démos | Deployments managés en entreprise |

---

## When to Use Standalone

Choose standalone if:
- You want to run occasional audits without any SaaS dependency
- You're evaluating the tool or running a POC
- You want full local control of all data
- You're integrating with your own SIEM or automation pipeline
- You're running in an air-gapped environment

→ [Standalone Mode Documentation](standalone.md)

---

## When to Use SaaS Daemon

Choose daemon mode if:
- You need centralized management of multiple AD environments / sites
- You want scheduled audits triggered remotely
- You have a SaaS subscription at `etcsec.com`
- You want automatic binary updates
- You need a persistent collector with remote visibility

→ [SaaS Daemon Documentation](saas-daemon.md)

---

## Both Modes Can Coexist

In daemon mode, the local GUI/API server can optionally run alongside the SaaS polling loop. Enable or disable it at any time without restarting the daemon:

```bash
# Enable local GUI (accessible on network)
etc-collector server enable --host 0.0.0.0 --port 8443

# Enable GUI for local access only
etc-collector server enable --host 127.0.0.1

# Disable local GUI
etc-collector server disable
```

> A non-loopback `--host` (`0.0.0.0` above) forces TLS — the GUI serves
> `https://` behind a bootstrap self-signed certificate, not `http://`. See
> [saas-daemon.md](saas-daemon.md#enable-the-gui) for the full rule and the
> `--allow-insecure-http` escape hatch.
