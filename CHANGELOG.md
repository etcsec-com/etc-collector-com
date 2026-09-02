# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed
- **⚠️ License changed: the whole product now ships under one license, FSL-1.1-ALv2** (Functional Source License, Version 1.1, Apache 2.0 Future License), replacing the previous split — Apache 2.0 for Community, a proprietary "ETC Collector License v1.0" for Pro. FSL permits free use, modification, self-hosting, and commercial/production use, including by companies; the one thing it forbids is using the software to build a competing product or service. Each release automatically converts to plain Apache License 2.0 two years after its publication date — a rolling window, not a one-time event. The root `LICENSE`, `public/LICENSE`, and the `license.txt` embedded in the binary (`etc-collector license`) now carry byte-identical text, sourced verbatim from [fsl.software](https://fsl.software/). `docs/EDITIONS.md` and every comparison/marketing page referencing the old license names are updated. `scripts/sync-public.sh` and `.pro-exclude` now also exclude `LICENSE` from the automatic public-repo sync: a licensing change is a standalone, deliberate act and must never ride along inside a routine content sync — this already happened once by accident (commits `e1b3ae4` → `9b66093`).
- **⚠️ `auth.tokenLifetime` is now applied to issued API tokens — on the Windows Service deployment only.** It was parsed from `config.yaml`, defaulted to 30 days, written into the generated Windows configuration as `tokenLifetime: 720h`, and returned by `GET /admin/config` — while token issuance used a hardcoded 24 h. A customer could read their own setting confirmed by our API and still receive 24-hour tokens. **Scope, verified path by path:** the Windows Service loads `config.yaml` (`service_windows.go:50`) and now honours the setting. The foreground `etc-collector server` command and the **Linux SaaS daemon — the default deployment** — build their configuration from `config.Default()` and never read the `auth:` section, so a custom `tokenLifetime` is still ignored there; that gap is tracked and not yet fixed. **Action required (Windows Service only):** if your `config.yaml` sets `auth.tokenLifetime` (the Windows installer writes `720h`), tokens issued from now on will last that long instead of 24 h. Set it explicitly to `24h` to keep the previous behaviour. A file with no `auth:` section is unaffected — the fallback stays 24 h. A duration given explicitly in the token request still wins over both.
- **`ldap.timeout` is no longer discarded** in `server` mode. The value from `config.yaml` was overwritten by a hardcoded 30 s immediately after being loaded, while the admin API echoed the file's value back. The default remains 30 s, so a file that omits the key is unchanged.
- **The `log:` section now works.** `log.level` and `log.format` were parsed and displayed but never applied — the logger was built before the configuration file was read. Precedence is `--verbose` > `ETCSEC_LOG_LEVEL` / `ETCSEC_LOG_FORMAT` > `config.yaml` > `info`/`console`.
- **Enrollment guides no longer lead with the token on the command line** — every guide that showed `--enroll-token YOUR_TOKEN` (or `enroll YOUR_TOKEN`) now prompts for it instead, so it never reaches `ps`, `/proc/<pid>/cmdline`, or your shell history. The flag remains supported and documented; it is simply no longer the first example. [CLI: enrollment](../docs/cli/enrollment.md#examples) now also documents where the token does **not** go: never into the systemd unit or Windows service definition, never into `credentials.json`, never into the logs.
- **Detection counts reconciled across the documentation** — `EDITIONS.md`, the feature pages and the fact sheet quoted three different sets of numbers, none matching the generated catalogs. All now derive from `make catalog`. The pages also now state which metric they use — unique detections, not registered detectors, which is what caused the drift. (Superseded below: the Community/Pro split these counts described no longer exists.)
- **⚠️ Single edition: the Community/Pro split is gone.** One binary now ships every detection — over 500, measured via `make catalog` (346 AD + 161 Azure). The `//go:build pro` tag and its build path are removed; `cmd/etc-collector/pro.go` (which only wired the still-unimplemented MCP server and HTML report stubs) is deleted rather than published unwired. `docs/EDITIONS.md` described a distribution model that no longer applies — including the private repo's own structure and release pipeline, information that had no business in a document shipped to every reader — and is replaced by a short `docs/LICENSING.md` covering the license alone. This release (v3.2.0) also publishes unsigned: no OV code-signing certificate exists yet for the Windows binary, and no detached signature covers the checksum file. Verify downloads via the published SHA-256 checksum in the meantime.

### Added
- **The `azure:` section of `config.yaml` is now used to run audits.** `etc-collector audit azure` previously accepted Entra credentials only as CLI flags: the section was parsed, shown by the admin API, prescribed by the documentation — and never used to authenticate. All six fields now resolve, including `clientCertPem`, whose multi-line PEM cannot be passed as a command-line argument. The `AZURE_*` environment variables work as documented for the same reason. `--tenant-id` and `--client-id` are consequently no longer rejected by the command parser before the file is read; they remain mandatory, and are now enforced after resolution.
- **One documented configuration precedence rule**, in `internal/config/precedence.go`: CLI flag > environment variable > `config.yaml` > built-in default. Cloud-managed collectors are unaffected — provider settings pushed by the SaaS live in `credentials.json` and never cross paths with `config.yaml`.

### Removed
- **Dead configuration keys `api:` and `saas.dataDir`.** Nothing read them. `api.port` was even validated, so a value outside 1–65535 could refuse to start a collector over a setting no code consulted. Both were already ignored in practice; they are now also absent from the configuration type, so `config.go` describes what the file really accepts. Conversely `enroll.token`, which worked but had no field, is now declared.

### Fixed
- **The admin API no longer drops Azure certificate credentials when saving the configuration** — `clientCertPath`, `clientCertPem` and `clientCertPassword` were absent from the config-writing path, so any save from the GUI silently deleted them from the file.
- **CI had never passed once** — 0 successes in 106 runs since 2026-04-06. Every Go job ran at the repository root, where there is no `go.mod` (the module lives in `public/`), so tests, lint and the vulnerability scan failed instantly and `build`/`docker` only ever reported "skipped" — nothing was ever compiled. A second stacked cause: the jobs pinned Go 1.22 while `go.mod` requires 1.24. Jobs now run in the module directory and read their Go version from `go.mod`, so it cannot drift again.
- **CI now builds the Pro edition too** (`-tags pro`) and syntax-checks the embedded GUI JavaScript — a JS syntax error compiles fine and breaks the whole GUI at runtime, which `go build` cannot detect.

### Removed
- **Codecov badge and upload** — this repository is private and has no upload token, so coverage was never published despite the badge claiming otherwise. Coverage is now a downloadable CI artifact.

### Security
- **The public release pipeline was still fail-open** — the previous fix covered only the private repo's workflow. `.github/workflows/release.yml` in this repo kept the `if: env.CODE_SIGN_PFX != ''` gate, so a missing certificate skipped signing and published anyway. It now fails closed exactly like the private pipeline, and a parity check in CI fails the build if the two ever diverge again.

### Changed
- **README no longer claims the Windows binary is code-signed.** It is not, and was not for any release through v3.1.39. Signing is enforced in CI (an unsignable release fails the build) and starts once an OV certificate is issued to ETCSEC.

### Added
- **Detached release signatures** — `checksums.sha256` is now published with a detached Sigstore signature bundle (`checksums.sha256.bundle`), so provenance can be verified independently of the download channel. Keyless signing via GitHub OIDC — no shared key to distribute.
- **`install.sh --require-signature`** — the installer verifies the detached signature when `cosign` is present and aborts if a published signature fails to verify. `--require-signature` makes verification mandatory rather than best-effort.
- **Verifying Downloads guide** — checksum, Sigstore, and Authenticode verification procedures for Linux, macOS, and Windows.

### Fixed
- **Releases could publish unsigned binaries silently** — the Windows Authenticode signing step was gated on `if: env.CODE_SIGN_PFX != ''`, so a missing CI secret skipped signing and published anyway with a green build. Signing is now enforced by a preflight gate: a release that cannot be signed **fails** instead. Releases v3.1.35–v3.1.39 were affected and shipped unsigned.
- **Signing would have failed on first use** — `osslsigncode -pkcs12` was handed the secret's contents where it expects a file path. The PKCS#12 bundle is now materialised to a real file (base64-decoded, mode 600, shredded afterwards).
- **Signatures are verified after signing** — a signing tool that reports success but produces an unsigned binary now fails the build instead of shipping.
- **Timestamping is resilient** — signatures are timestamped with a fallback server and retries; an untimestamped signature would expire with the certificate.

## [3.0.5] - 2026-04-04

### Added
- **Embedded GUI in daemon mode** — The SaaS daemon now serves the admin GUI locally alongside SaaS polling. Both modes run in the same process:
  - `--gui-host` flag: `127.0.0.1` (local only, default) or `0.0.0.0` (all interfaces)
  - `--gui-port` flag: default `8443`, set to `0` to disable
  - Engine and provider state is synchronized automatically when providers change (UPDATE_CONFIG, reconnection)
- **`server enable/disable` commands** — One-command GUI activation with interactive prompts:
  - `sudo etc-collector server enable` — interactive setup (host, port, confirmation)
  - `sudo etc-collector server enable --host 0.0.0.0 --port 8443 -y` — non-interactive
  - `sudo etc-collector server disable` — disables GUI, keeps SaaS daemon running
  - Updates systemd ExecStart, reloads and restarts service automatically
- **Interactive GUI prompt after SaaS install** — After enrolling with `etc-collector install --saas-url`, the installer asks whether to enable the local admin GUI with host/port selection
- **Audit report UI** — SaaS-style audit report with score ring, severity bars, infrastructure snapshot, and top findings grouped by category
- **"Want More?" promo banner** — Inline banner between Infrastructure Snapshot and Top Findings linking to etcsec.com/audit

### Fixed
- **Async audit 0 findings** — Fixed context cancellation in async goroutine: use `context.Background()` instead of `c.Request.Context()` which is cancelled when the 202 response is sent
- **Audit stats not parsing** — Fixed JSON path from `jobResult.score` to `jobResult.audit.summary.risk.score` (and all findings counts)
- **Severity bars invisible** — Alpine.js `:style` string was overwriting inline `style`, losing `height:100%` on the colored bar divs
- **Scan duration precision** — Format Go duration to 2 decimal places (e.g. `1.03s` instead of `1.028976218s`)
- **Auto-display audit results** — Audit results now auto-load when audit completes (no manual refresh needed)
- **Export JSON moved to header** — Export button repositioned next to audit header for visibility

## [3.0.4] - 2026-04-04

### Fixed
- **Update watcher killed by systemd** (`r-update-v3_0_3-B_01`) — The self-update watcher was silently killed by systemd's `KillMode=control-group`. Now uses `systemd-run --scope` to launch the watcher in its own transient scope unit, with fallback to `Setsid` on non-systemd systems.

## [3.0.3] - 2026-04-04

### Added
- **GUI access token authentication** — The admin GUI and sensitive API endpoints are now protected by an access token:
  - Token generated at install time or via `etc-collector gui-token reset`
  - Only SHA-256 hash stored on disk — plaintext shown once, never saved
  - `X-GUI-Token` header or `?gui_token=` query parameter
  - Protects `POST /api/v1/auth/token` and `/api/v1/admin/*` endpoints
  - `POST /api/v1/auth/gui-token/verify` endpoint for GUI login
  - Backwards-compatible: when no hash is configured, all requests pass through

## [3.0.2] - 2026-04-03

### Added
- **License embedding** — `etc-collector license` subcommand displays the full license text (embedded in binary at build time)
- License mention in install output

## [3.0.1] - 2026-04-03

### Fixed
- **Daemon resilience** — Atomic config save (temp + rename), backup recovery on corruption, panic-safe provider initialization

## [3.0.0] - 2026-04-02

### Added
- **Pro edition release process** — `scripts/release-pro.sh` builds cross-platform binaries with pro build tags
- Separate community/pro edition support via build tags

## [2.5.10] - 2026-02-16

### Enhanced
- **PIM Detectors** - Transformed 4 advisory detectors to active policy verification:
  - `PA_PIM_NOT_ENABLED` - Now checks specific sensitive roles for PIM configuration
  - `PA_PIM_NO_APPROVAL_REQUIRED` - Verifies RequiresApproval field for sensitive roles
  - `PA_PIM_NO_JUSTIFICATION` - Checks RequiresJustification for all eligible assignments
  - `PA_PIM_LONG_ACTIVATION` - Parses ISO 8601 duration and flags activations >8 hours

### Added
- ISO 8601 duration parser for PIM activation durations (`parseISO8601Duration`)
- `RoleAssignmentToAffectedEntity()` conversion function
- `RoleAssignmentsToAffectedEntities()` helper function

## [2.5.9] - 2026-02-16

### Added - TIER 1 (Critical)
- **LAPS Domain Coverage Detector** (`LAPS_DOMAIN_COVERAGE_LOW`)
  - Calculates LAPS deployment coverage: workstations, servers, overall
  - Severity thresholds: <80% High, <95% Medium
  - Matches Semperis Purple Knight coverage analysis

- **Enhanced Protected Users Detector** (`NOT_IN_PROTECTED_USERS`)
  - Extended detection: AdminCount=true + Administrator group members
  - Exclusions: krbtgt, administrator, service accounts with SPNs
  - Dual verification: user MemberOf + group Member lists
  - Matches Microsoft Secure Score recommendations

### Added - TIER 2 (High Priority)
- **Stale Privileged Accounts Detector** (`PRIVILEGED_ACCOUNT_STALE`)
  - Detects privileged accounts inactive >90 days
  - Uses LastLogonTimestamp/LastLogon
  - Matches Tenable.ad dormant account detection

- **Stale Computers in Admin Groups** (`COMPUTER_STALE_WITH_ADMIN_GROUPS`)
  - Identifies computers inactive >90 days in privileged groups
  - Flags highly unusual configurations

### Competitive Parity
- ✅ Microsoft Secure Score (Protected Users, PIM policies)
- ✅ Semperis Purple Knight (LAPS coverage analysis)
- ✅ Tenable.ad (temporal/stale account detection)
- ✅ CrowdStrike Falcon (PIM policy verification)

## [2.5.8] - 2026-02-16

### Added
- **PIM Policy Enrichment** - Role assignments now include PIM policy fields:
  - `RequiresJustification` (bool) - Justification required for activation
  - `RequiresApproval` (bool) - Approval required for activation
  - `ActivationDuration` (string) - Maximum activation duration (ISO 8601, e.g., "PT8H")

### API
- New `GetRoleManagementPolicies()` function in Azure client
- Fetches policies via `/roleManagement/directory/roleManagementPolicyAssignments?$expand=policy($expand=rules)`
- Policy map enrichment in `GetRoleAssignments()` with graceful degradation

### Requirements
- **New Azure Permission**: `RoleManagementPolicy.Read.Directory`
  - Required for PIM policy field population
  - Graceful degradation if permission missing (audit continues, fields remain empty)

### Data Types
- Added `RolePIMPolicy` struct in `types/azure.go`
- Extended `AzureEntityFields` with PIM policy fields in `types/finding.go`

## [2.4.1] - 2026-02-11

### Added
- **Azure CLI audit command**: `etc-collector audit azure` now fully functional
- Azure provider integration in audit engine
- CLI flags for Azure: `--tenant-id`, `--client-id`, `--client-secret`

### Fixed
- Azure audit command now executes audits (was returning "coming soon" error)
- Version number corrected from 2.3.8 to 2.4.1

## [2.4.0] - 2026-02-11

### Added
- **143 Azure Entra ID security detectors** - Full cloud identity audit support
- Azure provider integration with Microsoft Graph API
- Azure data collection in audit engine

### Azure Entra ID Security Detectors
- Applications (27): App registrations, permissions, secrets, service principals
- Conditional Access (20): Policies, controls, exclusions analysis
- Identity (21): Auth methods, MFA, password policy, SSPR, lifecycle
- Privileged Access (18): PIM, roles, emergency access
- Guest/External (15): B2B access, governance, external collaboration
- Groups (12): Membership, security group analysis
- Config (12): Logging, security settings, tenant configuration
- Compliance (8): Licensing, standards compliance
- Risk Protection (10): Identity protection, detection & response

### API Endpoints
- `POST /api/v1/audit/azure` - Run Azure Entra ID audit
- `GET /api/v1/audit/azure/status` - Azure audit status

## [2.1.0] - 2025-02-05

### Added
- GPO Links collection for GPO-based detectors
- GPO ACLs collection for permission analysis
- ACL collection for all permission-based detectors

### Fixed
- JSON response structure now matches TypeScript implementation
- Detector IDs aligned with TypeScript for SaaS compatibility
- Duplicate detector registration causing panic on startup
- Regex compatibility (removed unsupported Perl lookaheads)
- LDAP connection management (keep-alive for server mode)

### Changed
- Improved detector loading via init() registration
- Better error handling in LDAP provider

## [2.0.0] - 2025-02-05

### Changed
- **Complete rewrite in Go** - Single binary, no runtime dependencies
- Improved performance and reduced memory usage
- Native Windows support without Node.js

### Added
- 226 security detectors for Active Directory
- REST API with JWT authentication
- Docker support (linux/amd64, linux/arm64)
- Multi-platform binaries (Windows, Linux, macOS)
- Health check endpoint
- Structured JSON logging

### Security Detectors
- Accounts (32): Privileged accounts, service accounts, stale accounts
- Computers (26): LAPS, delegation, obsolete OS
- Kerberos (13): AS-REP roasting, Kerberoasting, delegation
- Permissions (15): Dangerous ACLs, GenericAll, WriteDACL
- Groups (15): Oversized groups, privileged membership
- GPO (9): Weak policies, unlinked GPOs
- ADCS (11): ESC1-11 certificate vulnerabilities
- Compliance (23): ANSSI, CIS, NIST, DISA frameworks
- Network (12): LDAP/SMB signing, DNSSEC
- Attack Paths (10): Privilege escalation paths

### API Endpoints
- `POST /api/v1/auth/token` - Generate JWT token
- `POST /api/v1/audit/ad` - Run AD audit
- `GET /api/v1/audit/ad/status` - Audit status
- `GET /api/v1/info/providers` - Provider info
- `GET /health` - Health check
