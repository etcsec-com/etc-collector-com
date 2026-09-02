# Vulnerability Catalogs

ETC Collector detects **over 500 unique security vulnerabilities** (507 confirmed live via `etc-collector audit list`, 2026-09-02) across Active Directory and Azure Entra ID — one binary, everything included, no edition split since v3.2.0. The exact total moves release to release — see the generated catalogs below for the current count.

---

## Detection Coverage

**Over 500 detections** across Active Directory and Azure/Entra ID, all in the single published binary — ADCS (ESC1–ESC11), Attack Paths, and Azure Risk Protection ship alongside everything else, no gating. For the current exact per-platform counts, regenerate with `make catalog` and read the totals from the catalog headers below — do not cite a number pinned here, it moves release to release.

---

## Severity Scale

Findings are classified into 5 levels:

| Severity | Weight | Score Impact | Meaning |
|----------|--------|--------------|---------|
| 🔴 Critical | 10 | High | Immediate exploitation risk, often weaponized |
| 🟠 High | 3 | Medium | Significant security gap, exploitable with effort |
| 🟡 Medium | 1 | Low | Configuration weakness, defense-in-depth issue |
| 🔵 Low | 0.2 | Minimal | Best practice violation, low direct risk |
| ⚪ Info | 0 | None | Informational finding, no scoring impact |

---

## Risk Score

Each domain gets a score from **0 (clean) to 100+ (critical)**. The score is computed from:

```
Score = Σ (severity_weight × entity_type_weight × finding_count)
```

Entity type weights reduce score inflation from bulk findings (e.g., 1,000 users without MFA counts less than 10 privileged accounts without MFA).

| Rating | Score | Meaning |
|--------|-------|---------|
| A | 0–10 | Excellent security posture |
| B | 10–25 | Good, minor gaps |
| C | 25–40 | Moderate issues to address |
| D | 40–60 | Significant vulnerabilities |
| F | 60–100 | Critical — immediate action required |

---

## Active Directory Catalog — Overview

By category (confirmed live 2026-09-02 against `AD_VULNERABILITY_CATALOG.md`, regenerated with `make catalog` — 346 detections total; see [Full AD Vulnerability Catalog](active-directory/AD_VULNERABILITY_CATALOG.md) for the row-by-row source of truth):

| Category | Detections | Critical | High | Medium | Low | Info |
|----------|-----------:|--------:|-----:|-------:|----:|----:|
| Password | 10 | 4 | 2 | 4 | 0 | 0 |
| Kerberos | 14 | 5 | 4 | 4 | 1 | 0 |
| Accounts | 32 | 3 | 14 | 12 | 2 | 1 |
| Groups | 17 | 1 | 7 | 8 | 0 | 1 |
| Computers | 34 | 10 | 9 | 8 | 4 | 3 |
| Advanced | 49 | 8 | 9 | 19 | 4 | 9 |
| Permissions | 23 | 3 | 10 | 9 | 0 | 1 |
| ADCS (ESC1–ESC11) | 11 | 3 | 6 | 2 | 0 | 0 |
| GPO | 35 | 6 | 9 | 15 | 4 | 1 |
| Trusts | 7 | 0 | 4 | 3 | 0 | 0 |
| Attack Paths | 3 | 2 | 1 | 0 | 0 | 0 |
| Monitoring | 8 | 0 | 4 | 3 | 1 | 0 |
| Compliance | 88 | 3 | 36 | 35 | 8 | 6 |
| Network | 15 | 0 | 7 | 2 | 3 | 3 |

All of the above ship in the single published binary — no edition gating since v3.2.0.

Notable detections:
- **AS-REP Roasting** (`ASREP_ROASTING_RISK`) — accounts without Kerberos pre-auth
- **Kerberoasting** (`KERBEROASTING_RISK`) — accounts with SPNs + weak encryption
- **ADCS ESC1–ESC11** — all 11 certificate template abuse paths classified
- **DCSync** (`DCSYNC_CAPABLE`) — non-DC accounts with replication rights
- **Zerologon enforcement** (`PA038_ZEROLOGON_ENFORCEMENT_OFF`) — CVE-2020-1472 mitigation
- **krbtgt rotation** (`ANSSI_R28_KRBTGT_NOT_ROTATED`) — Golden Ticket persistence risk
- **Compliance** — ANSSI PA-099, BP-039, Guide d'hygiène, HDS v1.1, RGPD, NIS2, CIS, NIST 800-53, DISA STIG (9 frameworks scored — see [`docs/configuration/compliance.md`](../configuration/compliance.md))
- **Attack Paths** — scored lateral movement chains through the domain

→ [Full AD Vulnerability Catalog](active-directory/AD_VULNERABILITY_CATALOG.md)

---

## Azure Entra ID Catalog — Overview

By category (confirmed live 2026-09-02 against `AZURE_VULNERABILITY_CATALOG.md`, regenerated with `make catalog` — 161 detections total; see [Full Azure Vulnerability Catalog](azure/AZURE_VULNERABILITY_CATALOG.md) for the row-by-row source of truth):

| Category | Detections | Notes |
|----------|-----------|-------|
| Identity | 29 | MFA, legacy auth, password policy, hybrid sync |
| Applications | 28 | Dangerous permissions, OAuth consent, CBA, SAML certs |
| Conditional Access | 20 | CA policy coverage and gaps |
| Privileged Access | 24 | PIM, permanent assignments, role thresholds |
| Guest & External | 15 | B2B, invitation policy |
| Config | 8 | Security defaults, tenant settings |
| Groups | 12 | Role-assignable groups, dynamic rules |
| Compliance | 8 | Licensing, access reviews |
| Risk Protection | 17 | Risky users, anomalous tokens |

All of the above ship in the single published binary — no edition gating since v3.2.0.

Notable detections:
- **Legacy Auth** (`LEGACY_AUTH_NOT_BLOCKED`) — primary vector for password spraying
- **No MFA** (`MFA_NOT_ENFORCED_ALL_USERS`) — the most common critical finding
- **Dangerous App Permissions** — `Directory.ReadWrite.All`, `Mail.ReadWrite`, `RoleManagement.ReadWrite.All`
- **Permanent Global Admin** (`PERMANENT_GLOBAL_ADMIN`) — without PIM protection
- **No PIM** (`PIM_NOT_CONFIGURED`) — no Privileged Identity Management deployed
- **Compromised Credentials** (`COMPROMISED_CREDENTIALS_DETECTED`) — Microsoft-detected leaks

→ [Full Azure Vulnerability Catalog](azure/AZURE_VULNERABILITY_CATALOG.md)

---

## Competitive Coverage

ETC Collector's detection engine covers the same attack surface as specialized tools:

| Tool | Their Checks | ETC Overlap | Coverage |
|------|-------------|-------------|---------|
| PingCastle 3.5 | 61 rules | 59/61 matched | **96.7%** |
| Purple Knight 5.0 | 119 indicators | 115/119 matched | **96.6%** |
| BloodHound 4.2 | Graph analysis | 39+ config types | Complementary |

ETC uniquely adds: **ADCS ESC1–ESC11 classification**, **scored attack paths**, **Azure Entra ID**, and **compliance frameworks**.

→ Detailed benchmarks against these tools are not yet part of `public/docs/`

---

## See Also

- [Features: Active Directory](../features/active-directory.md)
- [Features: Azure Entra ID](../features/azure-entra-id.md)
