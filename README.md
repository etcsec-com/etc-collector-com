# ETC Collector

> Security auditor for **Active Directory** and **Microsoft Entra ID** — single static Go binary, **over 500 security checks**, **9 compliance frameworks**.

[![Version](https://img.shields.io/github/v/release/etcsec-com/etc-collector-com?label=release&color=blue)](https://github.com/etcsec-com/etc-collector-com/releases/latest)
[![Go](https://img.shields.io/badge/Go-1.26+-00ADD8?logo=go&logoColor=white)](https://go.dev/)
[![License](https://img.shields.io/badge/license-FSL--1.1--ALv2-blue.svg)](LICENSE)
[![Docker](https://img.shields.io/docker/pulls/etcseccom/etc-collector?label=docker%20pulls)](https://hub.docker.com/r/etcseccom/etc-collector)
[![Last release](https://img.shields.io/github/release-date/etcsec-com/etc-collector-com)](https://github.com/etcsec-com/etc-collector-com/releases)
[![GitHub stars](https://img.shields.io/github/stars/etcsec-com/etc-collector-com?style=flat)](https://github.com/etcsec-com/etc-collector-com/stargazers)

ETC Collector audits an entire AD forest and outputs a single JSON document with framework-tagged compliance scores ready for **ANSSI**, **CIS**, **NIST**, **DISA**, **HDS**, **RGPD** and **NIS2** reporting. No agent. No Microsoft .NET dependency. No telemetry by default.

Cross-platform single binary covering ADCS escalation paths (ESC1–ESC11), Kerberos delegation abuse, AdminSDHolder tampering and Tier-0 privilege escalation — runs natively on Linux, macOS and Windows.

---

## Table of contents

- [Why this tool](#why-this-tool)
- [At a glance](#at-a-glance)
- [Architecture](#architecture)
- [Quick start](#quick-start)
- [Install](#install)
- [Operating modes](#operating-modes)
- [Detection coverage](#detection-coverage)
- [Compliance frameworks](#compliance-frameworks)
- [CLI reference](#cli-reference)
- [Configuration](#configuration)
- [Permissions](#permissions)
- [Output JSON schema](#output-json-schema)
- [REST API](#rest-api)
- [Build from source](#build-from-source)
- [Documentation](#documentation)
- [License](#license)
- [Support](#support)

---

## Why this tool

A senior identity-security engineer should immediately see what stands out:

- **Cross-platform single binary** — pure Go, ~50 MB on disk, no .NET, no Python, no JVM. Linux / macOS / Windows × amd64 / arm64.
- **AD + Microsoft Entra ID in one run** — emit a single JSON document covering both directories with consistent scoring.
- **Framework-tagged findings** — every detection carries the official compliance controls it satisfies (e.g. `compliance: [{framework: "ANSSI_PA099", control: "R28"}]`), and a per-framework score is computed in `summary.complianceScores[]`.
- **24 structured LDAP error codes** — instead of opaque Go runtime errors, classified codes such as `LDAP_TLS_IP_SAN_MISSING`, `LDAP_BIND_INVALID_CREDENTIALS`, `LDAP_REFERRAL_BAD_BASE_DN` are emitted with a fix suggestion and a doc anchor.
- **Three operating modes from one binary** — CLI one-shot for CI/CD, embedded HTTPS server with web UI, or long-running daemon enrolled with the [EtcSec SaaS](https://etcsec.com).
- **Stable JSON schema** — designed to be consumed downstream (SaaS dashboards, custom dashboards, SIEM ingestion).

---

## At a glance

Detector counts move release to release as detectors are added, split, or retired — see [`docs/vulnerabilities/README.md`](docs/vulnerabilities/README.md) for the current generated-catalog totals rather than a number pinned here.

| Metric | Value |
|---|---|
| Detectors | **over 500** across Active Directory and Microsoft Entra ID — one binary, everything included |
| Compliance frameworks | **9** scored per audit (PA-099, BP-039, Guide d'hygiène, HDS, RGPD, NIS2, CIS, NIST, DISA) |
| LDAP error codes | **24** structured codes |
| Binary size | ~10 MB compressed, ~50 MB on disk |
| Runtime dependencies | none — pure Go static binary |
| Build target Go version | 1.26+ |
| Supported OS / arch | linux/amd64, linux/arm64, darwin/amd64, darwin/arm64, windows/amd64 |

---

## Architecture

ETC Collector ships **one binary** that runs in three distinct modes:

```
┌───────────────────────────────────────────────────────────────────────┐
│                      ETC Collector v3.2.0                             │
├───────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌────────────────┐    ┌────────────────┐    ┌─────────────────────┐  │
│  │   1. CLI       │    │   2. Server    │    │   3. SaaS Daemon    │  │
│  │   one-shot     │    │   standalone   │    │   long-running poll │  │
│  ├────────────────┤    ├────────────────┤    ├─────────────────────┤  │
│  │ etc-collector  │    │ etc-collector  │    │ etc-collector       │  │
│  │ audit ad ...   │    │ server         │    │ daemon              │  │
│  │                │    │                │    │                     │  │
│  │ → stdout JSON  │    │ → HTTPS API    │    │ → enrolls with SaaS │  │
│  │ → exit 0/1     │    │   :8443 + GUI  │    │ → polls schedule    │  │
│  └───────┬────────┘    └───────┬────────┘    └─────────┬───────────┘  │
│          │                     │                       │              │
│          ▼                     ▼                       ▼              │
│   stdout / file          localhost:8443          api.etcsec.com       │
│                          web UI + REST                                 │
│                                                                         │
└───────────────────────────────────────────────────────────────────────┘
                                   │
                                   ▼
                          ┌─────────────────┐
                          │   Detector      │
                          │   Registry      │
                          │  (500+ checks)  │
                          └────────┬────────┘
                                   │
              ┌────────────────────┼────────────────────┐
              ▼                    ▼                    ▼
      ┌──────────────┐    ┌──────────────┐    ┌──────────────┐
      │  AD provider │    │ Entra ID     │    │  Future :    │
      │  ldap://     │    │ MS Graph SDK │    │  Exchange,   │
      │  ldaps://    │    │ Tenant ID +  │    │  Intune,     │
      │  + SMB SYSVOL│    │ Client cred  │    │  Workspace   │
      └──────────────┘    └──────────────┘    └──────────────┘
```

| Mode | Best for | Network | Persistence |
|---|---|---|---|
| **CLI** | CI/CD pipelines, ad-hoc audits, air-gapped environments | Outbound to DC only | None — JSON to stdout |
| **Server** | Local team dashboard, ad-hoc API integration | Outbound to DC + inbound HTTPS :8443 | Local SQLite (audit history) |
| **Daemon** | Centrally managed at scale via [EtcSec SaaS](https://etcsec.com) | Outbound to DC + outbound HTTPS to api.etcsec.com | Local config + enrollment token |

---

## Quick start

Images are published to two registries — pick either:
[Docker Hub `etcseccom/etc-collector`](https://hub.docker.com/r/etcseccom/etc-collector)
or `ghcr.io/etcsec-com/etc-collector`.

```bash
# 1. Pull the Docker image
docker pull etcseccom/etc-collector:latest
# …or from GitHub Container Registry:
# docker pull ghcr.io/etcsec-com/etc-collector:latest

# 2. Audit Active Directory (one-shot)
mkdir -p output && chmod 777 output   # the image runs as non-root uid 1000
docker run --rm -v "$(pwd)/output":/output \
  etcseccom/etc-collector:latest \
  audit ad \
  --ldap-url ldaps://dc01.example.com:636 \
  --ldap-bind-dn "CN=svc-etccollector,CN=Users,DC=example,DC=com" \
  --ldap-bind-password "$LDAP_BIND_PASSWORD" \
  --ldap-base-dn "DC=example,DC=com" \
  -o /output/audit.json

# 3. Inspect the result
jq '.audit.summary | {findings: .risk.findings.total, score: .risk.score, frameworks: [.complianceScores[].framework]}' output/audit.json
```

> **`-e LDAP_URL=...` does not work here yet.** `environment-variables.md` documents `LDAP_URL`/`LDAP_BIND_DN`/`LDAP_BIND_PASSWORD`/`LDAP_BASE_DN` as valid for LDAP connections, and they genuinely are for `server`/`daemon` mode — confirmed live: `env LDAP_URL=... etc-collector server` picks them up with no flags. But the one-shot `audit ad`/`audit azure`/`discover` subcommands don't bind them (confirmed live, native binary and Docker both): with only those env vars set and no flags, the command fails with `required flag(s) "ldap-base-dn", "ldap-bind-dn", "ldap-bind-password", "ldap-url" not set`. Use explicit `--ldap-*` flags for one-shot audits as shown above until this is fixed — tracked, not a doc-side workaround.
>
> **`-o /dev/stdout > audit.json` also does not work.** Progress logs write to the same stdout stream as the JSON result, corrupting the file mid-object (confirmed live: the resulting file fails `jq` parsing with `Invalid string: control characters`). Write to a real path (as above) instead — this is B_192, already tracked.

`LDAP_BIND_DN` above is a **read-only service account you create first** in your own Active Directory — see [Permissions](#permissions) below for the exact one-time setup, and substitute your own domain for `example.com`/`DC=example,DC=com` throughout this page.

See [`docs/configuration/ad-getting-started.md`](docs/configuration/ad-getting-started.md) for a guided walkthrough including DC certificate extraction and 5 connection scenarios.

---

## Install

### Verify the download

Every release ships a `checksums.sha256` file alongside the binaries.

```bash
VERSION=3.2.0
BASE=https://github.com/etcsec-com/etc-collector-com/releases/download/v${VERSION}

# Download the binary + the checksums
curl -LO ${BASE}/etc-collector-${VERSION}-linux-amd64.tar.gz
curl -LO ${BASE}/checksums.sha256

# Verify
sha256sum -c checksums.sha256 --ignore-missing
# → etc-collector-3.2.0-linux-amd64.tar.gz: OK
```

### Linux

```bash
VERSION=3.2.0
curl -LO https://github.com/etcsec-com/etc-collector-com/releases/download/v${VERSION}/etc-collector-${VERSION}-linux-amd64.tar.gz
tar -xzf etc-collector-${VERSION}-linux-amd64.tar.gz
sudo install -m 0755 etc-collector-${VERSION}-linux-amd64/etc-collector /usr/local/bin/etc-collector
etc-collector --version
```

### macOS

```bash
ARCH=$(uname -m | sed 's/x86_64/amd64/')
VERSION=3.2.0
curl -LO https://github.com/etcsec-com/etc-collector-com/releases/download/v${VERSION}/etc-collector-${VERSION}-darwin-${ARCH}.tar.gz
tar -xzf etc-collector-${VERSION}-darwin-${ARCH}.tar.gz
sudo install -m 0755 etc-collector-${VERSION}-darwin-${ARCH}/etc-collector /usr/local/bin/etc-collector

# If Gatekeeper blocks the binary
sudo xattr -rd com.apple.quarantine /usr/local/bin/etc-collector
```

### Windows (PowerShell)

```powershell
$Version = "3.2.0"
$Base = "https://github.com/etcsec-com/etc-collector-com/releases/download/v$Version"
Invoke-WebRequest -Uri "$Base/etc-collector-$Version-windows-amd64.zip" -OutFile etc-collector.zip
Expand-Archive etc-collector.zip -DestinationPath . -Force
New-Item -ItemType Directory -Force -Path "C:\Program Files\ETCSec" | Out-Null
Move-Item ".\etc-collector-$Version-windows-amd64\etc-collector.exe" "C:\Program Files\ETCSec\etc-collector.exe" -Force

# Optional : install as Windows service
& "C:\Program Files\ETCSec\etc-collector.exe" install
```

> **This release (v3.2.0) is published unsigned.** No Authenticode signature on
> the Windows binary (no OV code-signing certificate has been issued yet), and
> no detached signature on the checksum file. Windows SmartScreen will warn and
> AppLocker/WDAC policies may block the binary. Signing is enforced by default
> in CI going forward — a release that cannot be signed fails the build instead
> of publishing silently unsigned — this one shipped through the documented
> opt-out. Verify your download with the published SHA-256 checksum
> (`checksums.sha256`) instead — see [Verify the download](#install) above.

### Docker

Pinned to a version, from either registry — see
[Docker Hub](https://hub.docker.com/r/etcseccom/etc-collector) for the tag list.

```bash
docker pull etcseccom/etc-collector:3.2.0
# …or: docker pull ghcr.io/etcsec-com/etc-collector:3.2.0

mkdir -p output && chmod 777 output   # the image runs as non-root uid 1000
docker run --rm \
  -v /etc/ssl/certs:/etc/ssl/certs:ro \
  -v "$(pwd)/output":/output \
  etcseccom/etc-collector:3.2.0 \
  audit ad \
  --ldap-url ldaps://dc01.example.com:636 \
  --ldap-bind-dn "CN=svc-etccollector,CN=Users,DC=example,DC=com" \
  --ldap-bind-password "$LDAP_BIND_PASSWORD" \
  --ldap-base-dn "DC=example,DC=com" \
  -o /output/audit.json
```

> `-e LDAP_*` env vars and `-o /dev/stdout` don't work for one-shot `audit`/`discover` — see the callout in [Quick start](#quick-start) above.

### Docker Compose

```yaml
services:
  etc-collector:
    image: etcseccom/etc-collector:3.2.0
    container_name: etc-collector
    restart: unless-stopped
    ports:
      - "8443:8443"
    command:
      - server
      - --ldap-url=ldaps://dc01.example.com:636
      - --ldap-bind-dn=CN=svc-etccollector,CN=Users,DC=example,DC=com
      - --ldap-bind-password=${LDAP_BIND_PASSWORD}
      - --ldap-base-dn=DC=example,DC=com
    volumes:
      - collector-data:/app/data
      - ./keys:/app/keys:ro

volumes:
  collector-data:
```

---

## Operating modes

### 1. CLI (one-shot)

Best for CI/CD, ad-hoc audits, and air-gapped environments. The binary connects, audits, prints JSON, exits.

```bash
etc-collector audit ad --ldap-url ldaps://dc:636 ... -o audit.json
echo "exit=$?"
```

Exit codes :
- `0` — audit completed (findings may exist)
- `1` — audit failed (LDAP error, network error, file write error...)

### 2. Standalone server

Local HTTPS API + embedded GUI. No cloud, no enrollment.

```bash
etc-collector server --port 8443
# → https://localhost:8443
# → REST API at /api/v1/*
```

A web UI is served at the root; a REST API allows scripting audits and pulling job results. JWT auth required.

### 3. SaaS daemon

The collector enrolls with the [EtcSec SaaS](https://etcsec.com) platform, polls for audit commands, and uploads results to your dashboard. Configuration and scheduling are managed centrally.

```bash
etc-collector enroll YOUR_TOKEN --saas-url https://api.etcsec.com
sudo systemctl enable --now etcsec-collector
```

The daemon also serves the local admin GUI alongside SaaS operations. By default the GUI listens on `127.0.0.1:8443`. Use `--gui-host 0.0.0.0` to expose it (and configure firewall + access token).

→ See [`docs/modes/`](docs/modes/) for the full mode comparison.

---

## Detection coverage

One binary, every category included — no edition gating.

### Active Directory — by category

| Category | Total | Severity distribution |
|---|---:|---|
| accounts | 32 | 3🔴 / 14🟠 / 12🟡 / 2🔵 / 1⚪ |
| password | 10 | 4🔴 / 2🟠 / 4🟡 |
| kerberos | 14 | 5🔴 / 4🟠 / 4🟡 / 1🔵 |
| computers | 34 | 10🔴 / 9🟠 / 8🟡 / 4🔵 / 3⚪ |
| groups | 17 | 1🔴 / 7🟠 / 8🟡 / 1⚪ |
| permissions | 23 | 3🔴 / 10🟠 / 9🟡 / 1⚪ |
| gpo | 35 | 6🔴 / 9🟠 / 15🟡 / 4🔵 / 1⚪ |
| monitoring | 8 | 4🟠 / 3🟡 / 1🔵 |
| network | 15 | 7🟠 / 2🟡 / 3🔵 / 3⚪ |
| trusts | 7 | 4🟠 / 3🟡 |
| advanced | 49 | 8🔴 / 9🟠 / 19🟡 / 4🔵 / 9⚪ |
| compliance | 88 | 3🔴 / 36🟠 / 35🟡 / 8🔵 / 6⚪ |
| adcs *(ESC1–ESC11)* | 11 | 3🔴 / 6🟠 / 2🟡 |
| attack-paths | 3 | 2🔴 / 1🟠 |

### Microsoft Entra ID — by category

| Category | Total | Notes |
|---|---:|---|
| identity | 29 | MFA, SSPR, hybrid sync, lifecycle, legacy auth, password policy |
| applications | 28 | App registrations, service principals, OAuth consent, SAML certs |
| privileged-access | 24 | PIM, role assignments, eligible vs active, role thresholds |
| conditional-access | 20 | CA policy coverage, exclusions, gaps |
| guest-external | 15 | B2B, invitation policy, stale guests |
| groups | 12 | Role-assignable, dynamic membership, owner gaps |
| config | 8 | Tenant settings, security defaults, user consent |
| compliance (azureCompliance) | 8 | Access reviews, P2 license usage, CIS gaps, terms of use |
| risk-protection | 17 | Identity Protection, leaked credentials, sign-in/user risk policies |

> Per-category counts above are a snapshot; the generated catalogs are the
> source of truth and move as detectors are added, split, or retired.

→ **Browse the live catalog: [etcsec.com/vulnerabilities](https://etcsec.com/en/vulnerabilities)** — always current, no rebuild needed.
The generated snapshots in this repo — [`docs/vulnerabilities/active-directory/`](docs/vulnerabilities/active-directory/) and [`docs/vulnerabilities/azure/`](docs/vulnerabilities/azure/) — match the binary you downloaded: over 500 unique detections combined.

---

## Compliance frameworks

ETC Collector tags every finding with the compliance controls it satisfies, then computes per-framework scores in `summary.complianceScores[]`. Nine frameworks ship in v3.2.0, all referenced against their **official publication identifiers**.

| Framework key (in JSON) | Coverage | Official publication |
|---|---:|---|
| `ANSSI_PA099` | 90 detectors | [ANSSI-PA-099 v1.0 — Recommandations pour l'administration sécurisée des SI reposant sur Microsoft Active Directory](https://cyber.gouv.fr/publications/recommandations-de-securite-relatives-active-directory) (02/10/2023) |
| `ANSSI_BP039` | 3 detectors | [ANSSI-BP-039 v1.0 — Mise en œuvre des fonctionnalités de sécurité de Windows 10 reposant sur la virtualisation](https://cyber.gouv.fr/publications/mise-en-oeuvre-des-fonctionnalites-de-securite-de-windows-10-reposant-sur-la) (11/2017) |
| `ANSSI_GUIDE_HYGIENE` | 18 detectors | [ANSSI Guide d'hygiène informatique](https://cyber.gouv.fr/publications/guide-dhygiene-informatique) (40 mesures essentielles) |
| `HDS_v1_1` | 40 detectors | [Référentiel HDS v1.1](https://esante.gouv.fr/produits-services/hds) — Hébergement Données de Santé (Agence du Numérique en Santé) |
| `RGPD` | 21 detectors | [RGPD article 32](https://eur-lex.europa.eu/legal-content/FR/TXT/?uri=CELEX%3A32016R0679) — Sécurité du traitement (UE 2016/679) |
| `NIS2_FR` | 42 detectors | [Directive UE 2022/2555 (NIS2)](https://eur-lex.europa.eu/eli/dir/2022/2555/oj), transposition FR loi 2024-449 |
| `CIS_v8` | 19 detectors | [CIS Controls v8.1 (May 2024)](https://www.cisecurity.org/controls/v8) + CIS Microsoft Windows Server 2022 Benchmark v3.0.0 |
| `NIST_800_53` | 20 detectors | [NIST SP 800-53 Rev.5 (Sept 2020, patch 2023)](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final) — AC, AU, IA control families |
| `DISA_STIG` | 8 detectors | [DISA STIG — Active Directory Domain V3R3](https://public.cyber.mil/stigs/downloads/) |

Each framework also exposes a **scope profile** so you can run only the detectors relevant to it:

```bash
etc-collector audit ad ... --scope-profile compliance-anssi
etc-collector audit ad ... --scope-profile compliance-cis
# ... compliance-anssi-bp039, compliance-anssi-hyg, compliance-hds,
#     compliance-rgpd, compliance-nis2, compliance-nist, compliance-disa
```

→ See [`docs/configuration/compliance.md`](docs/configuration/compliance.md) for the full mapping table and a per-control breakdown.

---

## CLI reference

The full command tree (output of `etc-collector --help` v3.2.0):

```
etc-collector
├── audit          Run a one-shot security audit
│   ├── ad         Audit Active Directory (LDAP / LDAPS / StartTLS)
│   ├── azure      Audit Microsoft Entra ID
│   ├── exchange   Audit Exchange Online (mailbox delegation, forwarding)
│   ├── intune     Audit Microsoft Intune (device compliance, encryption)
│   ├── google     Audit Google Workspace (2FA, OAuth, drive sharing)
│   └── list       List available detector categories, profiles and IDs
├── discover       List assets without running detectors (read-only preview)
├── server         Manage the local admin GUI & API server
├── daemon         Run in daemon mode (SaaS)
├── enroll         Enroll this collector with the SaaS platform
├── unenroll       Remove enrollment
├── status         Show enrollment status
├── trial          Run a one-shot anonymous trial session
├── install        Install ETC Collector as a system service
├── uninstall      Uninstall the system service
├── upgrade        Upgrade the etc-collector binary out-of-process (v3.1.15+)
├── service        Manage the running service
├── gui-token      Manage GUI access token
├── compliance     Compliance catalog diagnostics (see docs/configuration/compliance.md)
├── license        Display the software license
├── help           Help about any command
└── completion     Generate shell autocompletion (bash, zsh, fish, powershell)
```

### `audit ad` — full flag reference

Flags below are confirmed live against `etc-collector audit ad --help` v3.2.0
and grouped by theme for readability — the real `--help` output is a flat,
alphabetically-sorted list without these section headers:

```
LDAP connection
  --ldap-url string                  ldap:// or ldaps:// URL (REQUIRED)
  --ldap-bind-dn string              Bind DN (DN, UPN or NetBIOS form) (REQUIRED)
  --ldap-bind-password string        Bind password (REQUIRED)
  --ldap-base-dn string              Search base DN (REQUIRED)

TLS
  --ldap-tls-verify                  Verify LDAP TLS certificates (default true)
  --ldap-ca-cert string              Path to a PEM file with the CA chain
  --ldap-tls-min-version string      Min TLS version: 1.0 / 1.1 / 1.2 / 1.3
  --ldap-start-tls                   Upgrade ldap:// (port 389) to TLS via StartTLS

Audit scope
  --scope-profile string             quick | compliance | pentest |
                                     compliance-anssi | compliance-anssi-bp039 |
                                     compliance-anssi-hyg | compliance-hds |
                                     compliance-rgpd | compliance-nis2 |
                                     compliance-cis | compliance-nist | compliance-disa
  --scope-include-categories strings Categories to include (comma-separated)
  --scope-exclude-categories strings Categories to exclude
  --scope-include-detectors  strings Detector IDs to include
  --scope-exclude-detectors  strings Detector IDs to exclude
  --exclusions string                Path to an exclusions.yaml file
  --exclusions-dry-run               Compute exclusions without applying them

Network probes
  --enable-network-probes            Enable HTTP/HTTPS reach probes for ADCS, DNS AXFR

Output
  --format string                    json | json-pretty (default json)
  --include-details                  Include affected entities (default true)
  -o, --output string                Output file path (default stdout)

Reproducibility
  --as-of string                     Reference time (RFC3339) recency detectors measure
                                     against. Default: the real moment the audit runs.
                                     Lets a frozen benchmark replay identically on a
                                     later date.

Global
  --config string                    Path to config.yaml
  -V, --verbose                      Enable verbose/debug output
```

---

## Configuration

ETC Collector reads configuration in this priority (highest first):

1. CLI flags
2. Environment variables
3. `config.yaml` (searched in `./`, `~/.etc-collector/`, `/etc/etc-collector/`)
4. Built-in defaults

### Minimal `config.yaml`

```yaml
# Server mode settings (only needed for `etc-collector server`)
server:
  host: "127.0.0.1"
  port: 8443
  tls:
    cert: /etc/etc-collector/server.crt
    key:  /etc/etc-collector/server.key

# Active Directory connection (used by `etc-collector audit ad`)
ldap:
  url: ldaps://dc01.example.com:636
  bind_dn: "CN=svc-etccollector,CN=Users,DC=example,DC=com"
  bind_password: ${LDAP_BIND_PASSWORD}     # env var expansion
  base_dn: "DC=example,DC=com"
  tls_ca_cert: /etc/etc-collector/rootca.pem
  tls_verify: true

# Microsoft Entra ID
azure:
  tenant_id: ${AZURE_TENANT_ID}
  client_id: ${AZURE_CLIENT_ID}
  client_secret: ${AZURE_CLIENT_SECRET}

# Default audit scope
audit:
  scope_profile: compliance
```

### Key environment variables

| Variable | Purpose |
|---|---|
| `LDAP_URL`, `LDAP_BIND_DN`, `LDAP_BIND_PASSWORD`, `LDAP_BASE_DN` | LDAP connection |
| `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET` | Entra ID app registration |
| `AUDIT_INCLUDE_CATEGORIES`, `AUDIT_EXCLUDE_CATEGORIES` | Equivalent to `--scope-*` flags |
| `AUDIT_PROFILE` | Equivalent to `--scope-profile` |
| `SERVER_PORT`, `AUTH_JWT_SECRET` | Server mode |

→ Full reference: [`docs/configuration/environment-variables.md`](docs/configuration/environment-variables.md)

---

## Permissions

### Active Directory — read-only service account

A standard `Domain Users` member is **enough for the full audit**: LDAP read on objects, SMB read on `\\<domain>\SYSVOL` (default for `Authenticated Users`), and read access to audit policy via the registry-replicated GPO objects.

```powershell
# Create a dedicated, non-rotating, non-delegated read-only account
New-ADUser -Name "svc-etccollector" `
  -SamAccountName "svc-etccollector" `
  -UserPrincipalName "svc-etccollector@example.com" `
  -AccountPassword (Read-Host -AsSecureString "Password") `
  -Enabled $true `
  -PasswordNeverExpires $true `
  -CannotChangePassword $true

Set-ADAccountControl -Identity svc-etccollector -AccountNotDelegated $true
```

Do **not** put this account in `Domain Admins`, `Backup Operators`, or any privileged group — read-only is the entire model.

### Microsoft Entra ID — app registration with application permissions

```bash
APP_NAME="ETC-Collector-Audit"

az ad app create --display-name "$APP_NAME"
APP_ID=$(az ad app list --display-name "$APP_NAME" --query "[0].appId" -o tsv)
az ad app credential reset --id "$APP_ID" --append --years 2

for PERM in \
  "User.Read.All" \
  "AuditLog.Read.All" \
  "UserAuthenticationMethod.Read.All" \
  "Directory.Read.All" \
  "Application.Read.All" \
  "Policy.Read.All" \
  "RoleManagement.Read.All" \
  "IdentityRiskyUser.Read.All"
do
  az ad app permission add --id "$APP_ID" \
    --api 00000003-0000-0000-c000-000000000000 \
    --api-permissions $(az ad sp show --id 00000003-0000-0000-c000-000000000000 \
        --query "appRoles[?value=='$PERM'].id | [0]" -o tsv)=Role
done

az ad app permission admin-consent --id "$APP_ID"
```

→ Step-by-step: [`docs/configuration/permissions.md`](docs/configuration/permissions.md)

---

## Output JSON schema

A single audit produces one JSON document with this top-level shape:

Confirmed live against a real v3.2.0 audit (2026-09-02) — two fields in
earlier versions of this example didn't exist in the real output
(`summary.objects.findings` and `attackGraph.totalPaths`) and are fixed
below; `metadata` is now shown in its real nested shape:

```jsonc
{
  "success": true,
  "provider": "ad",
  "audit": {
    "metadata": {
      "provider": "ad",
      "domain": { "name": "example", "baseDN": "DC=example,DC=com", "ldapUrl": "ldaps://dc01.example.com:636" },
      "options": { "includeDetails": true, "includeComputers": true, "includeConfig": true },
      "execution": { "timestamp": "2026-04-22T20:21:00Z", "duration": "1.08s" }
    },
    "summary": {
      "objects": {
        "users": 546, "users_enabled": 27, "users_disabled": 519,
        "groups": 154, "ous": 352, "computers": 100
      },
      "risk": {
        "score": 33, "rating": "high",
        "findings": { "critical": 3, "high": 40, "medium": 51, "low": 20, "info": 0, "total": 114, "totalInstances": 270, "records": 270 }
      },
      "complianceScores": [
        {
          "framework": "ANSSI_PA099",
          "score": 40.4, "rating": "high",
          "controlsTotal": 52, "controlsPassed": 21, "controlsFailed": 31, "controlsManual": 37,
          "failedControls": ["R1", "R2", "R6", "R22", "R28"],
          "maturityAxes": [
            {"name": "Politique de mot de passe", "level": 3, "coverage": 0.6},
            {"name": "Comptes privilégiés",        "level": 2, "coverage": 0.4},
            {"name": "Authentification",           "level": 4, "coverage": 0.8},
            {"name": "Délégation",                 "level": 1, "coverage": 0.2},
            {"name": "Supervision & audit",        "level": 3, "coverage": 0.6}
          ]
        }
      ]
    },
    "accounts":      { "findings": [/* ... */] },
    "computers":     { "findings": [/* ... */] },
    "groups":        { "findings": [/* ... */] },
    "permissions":   { "findings": [/* ... */] },
    "adcs":          { "findings": [/* ... */] },
    "gpoSecurity":   { "findings": [/* ... */] },
    "trustsAnalysis":{ "findings": [/* ... */] },
    "domainConfig":  { "domainInfo": {/* ... */}, "passwordPolicy": {/* ... */}, "kerberosPolicy": {/* ... */} },
    "security":      { "passwords": {/* ... */}, "kerberos": {/* ... */}, "advanced": {/* ... */} },
    "attackGraph":   {
      "targets": [/* ... */], "uniqueNodes": 83,
      "paths":   [{ "id": "path-001", "risk": "critical", "type": "DCSYNC", "hops": 1, "chain": [/* ... */] }]
    }
  }
}
```

Every finding object embeds its compliance mapping:

```jsonc
{
  "type": "NTLMV1_ALLOWED",
  "severity": "high",
  "category": "advanced",
  "title": "NTLMv1 Authentication Allowed",
  "description": "...",
  "count": 1,
  "compliance": [
    {"framework": "ANSSI_PA099", "control": "R22"},
    {"framework": "RGPD",        "control": "art.32(1)(a)"},
    {"framework": "NIS2_FR",     "control": "Art.21(2)(h)"},
    {"framework": "CIS_v8",      "control": "§2.3"}
  ],
  "affectedEntities": []
}
```

On error, the document includes a structured code that matches one of the **24 LDAP error codes** documented in [`docs/configuration/ad-troubleshooting.md`](docs/configuration/ad-troubleshooting.md):

```jsonc
{
  "success": false,
  "error": {
    "code": "LDAP_TLS_IP_SAN_MISSING",
    "message": "LDAP URL uses an IP address but the certificate has no IP SAN",
    "resolution": "Use the DC FQDN listed in the certificate SAN.",
    "raw": "tls: failed to verify certificate: x509: cannot validate certificate for 10.0.0.10 because it doesn't contain any IP SANs"
  }
}
```

---

## REST API

When running in `server` mode, ETC Collector exposes a REST JSON API at `http://<host>:8443/api/v1/` (or `https://` once `server.tls.cert`/`server.tls.key` are configured — with no TLS configured, the server binds plain HTTP, confirmed live on v3.2.0). GUI-token auth to mint a JWT, then JWT bearer auth for everything else.

```bash
HOST=http://localhost:8443
GUI_TOKEN="etcsec_gt_..."   # shown once at install time, or: etc-collector gui-token reset

# 1. Mint a JWT from the GUI access token
JWT=$(curl -s -X POST $HOST/api/v1/auth/token \
  -H "Content-Type: application/json" \
  -H "X-GUI-Token: $GUI_TOKEN" \
  -d '{"service":"automation","duration":"24h"}' | jq -r .token)

# 2. Trigger an async audit
JOB_ID=$(curl -s -X POST $HOST/api/v1/audit/ad \
  -H "Authorization: Bearer $JWT" \
  -d '{"async": true}' | jq -r .jobId)

# 3. Poll job status — the result is embedded in this same response once status is "completed"
curl -s $HOST/api/v1/audit/jobs/$JOB_ID -H "Authorization: Bearer $JWT" | jq '{status, result}' > result.json

# 4. Liveness probe (no auth)
curl -s $HOST/health
```

→ Full endpoint reference: [`docs/API.md`](docs/API.md)

---

## Build from source

Requires **Go 1.26+** (matches `go 1.26.7` in `go.mod`).

```bash
git clone https://github.com/etcsec-com/etc-collector-com.git
cd etc-collector-com

# Build
make build
# OR manually
go build -o etc-collector ./cmd/etc-collector/

# Cross-compile for every supported target
mkdir -p dist
for target in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64; do
  OS=${target%/*}; ARCH=${target#*/}
  EXT=""; [ "$OS" = "windows" ] && EXT=".exe"
  GOOS=$OS GOARCH=$ARCH CGO_ENABLED=0 go build \
    -ldflags="-s -w" \
    -o dist/etc-collector-$OS-$ARCH$EXT \
    ./cmd/etc-collector/
done
```

Build flags:
- `CGO_ENABLED=0` — pure-Go static binary (no glibc dependency)
- `-ldflags="-s -w"` — strip debug info, ~30% smaller binary

---

## Documentation

| Topic | File |
|---|---|
| **Getting started (admin walkthrough)** | [`docs/configuration/ad-getting-started.md`](docs/configuration/ad-getting-started.md) |
| AD connection modes (LDAP/LDAPS/StartTLS) | [`docs/configuration/ad-connection-modes.md`](docs/configuration/ad-connection-modes.md) |
| AD TLS certificate extraction (5 methods) | [`docs/configuration/ad-tls-certificates.md`](docs/configuration/ad-tls-certificates.md) |
| AD troubleshooting runbook (24 error codes) | [`docs/configuration/ad-troubleshooting.md`](docs/configuration/ad-troubleshooting.md) |
| Audit scope (categories / IDs / profiles) | [`docs/configuration/audit-scope.md`](docs/configuration/audit-scope.md) |
| Compliance frameworks (mapping table) | [`docs/configuration/compliance.md`](docs/configuration/compliance.md) |
| Permissions (AD account & Azure app setup) | [`docs/configuration/permissions.md`](docs/configuration/permissions.md) |
| Configuration reference | [`docs/configuration/`](docs/configuration/) |
| AD vulnerability catalog | [`docs/vulnerabilities/active-directory/AD_VULNERABILITY_CATALOG.md`](docs/vulnerabilities/active-directory/AD_VULNERABILITY_CATALOG.md) |
| Azure vulnerability catalog | [`docs/vulnerabilities/azure/AZURE_VULNERABILITY_CATALOG.md`](docs/vulnerabilities/azure/AZURE_VULNERABILITY_CATALOG.md) |
| Operating modes (Standalone vs SaaS daemon) | [`docs/modes/`](docs/modes/) |
| Features overview | [`docs/features/`](docs/features/) |
| REST API reference | [`docs/API.md`](docs/API.md) |
| Licensing | [`docs/LICENSING.md`](docs/LICENSING.md) |

---

## License

**One binary, one license — since v3.2.0 there is no Community/Pro split.** AD audit, Microsoft Entra ID audit, ADCS (ESC1–ESC11), attack-paths, Azure Risk Protection, the REST API, the embedded GUI, standalone server mode and SaaS daemon mode all ship in the same download.

ETC Collector is licensed under the **[Functional Source License, Version 1.1, Apache 2.0 Future License (FSL-1.1-ALv2)](LICENSE)**. You are free to use, modify, self-host and run this software in production — including commercial and enterprise use — but not to build a product or service that competes with ETC Collector. Each release automatically converts to the permissive **Apache License 2.0** two years after its publication date. See the [`LICENSE`](LICENSE) file for full terms, [`docs/LICENSING.md`](docs/LICENSING.md) for more detail, and [fsl.software](https://fsl.software/) for the official license text.

If you are unsure whether your intended use is a Competing Use under the license, contact `support@etcsec.com`.

---

## Support

- **Documentation** — [etcsec.com](https://etcsec.com)
- **Issues** — [github.com/etcsec-com/etc-collector-com/issues](https://github.com/etcsec-com/etc-collector-com/issues) for bug reports and feature requests
- **Security** — `security@etcsec.com` (responsible disclosure, 48-hour acknowledgment)
- **Commercial / Pro / SaaS** — `support@etcsec.com`
