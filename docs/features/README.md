# Features

ETC Collector audits two major identity platforms and produces structured, machine-readable results in seconds.

---

## Platforms Supported

Confirmed live 2026-09-02 (`etc-collector audit list` + `make catalog`) — one binary, everything included, no Community/Pro split since v3.2.0:

| Platform | Protocol | Detections | Categories |
|----------|----------|-----------:|-----------:|
| [Active Directory](active-directory.md) | LDAP / LDAPS / SMB | 346 | 14 |
| [Azure Entra ID](azure-entra-id.md) | Microsoft Graph API | 161 | 9 |
| **Total** | | **507** | **23** |

---

## What Gets Analyzed

### Active Directory
ETC connects to your domain controllers over LDAP/LDAPS and SYSVOL (SMB), collecting:
- User accounts (all attributes, UAC flags, password policy, delegation, SID history)
- Groups (membership, nesting, privileged groups, ownership)
- Computers (OS version, delegation, LAPS, BitLocker, location in OU)
- GPOs (security settings, permissions, links, registry policies)
- Domain/forest trusts (direction, transitivity, SID filtering)
- ACLs (object-level permissions — GenericAll, WriteDACL, DCSync rights, etc.)
- AD CS (certificate templates, CA configuration)
- Kerberos policy (ticket lifetimes, encryption types, pre-auth settings)

### Azure Entra ID
ETC calls Microsoft Graph API with an app registration, collecting:
- Users (MFA status, password age, risk level, auth methods)
- Groups (dynamic rules, owners, privileged memberships)
- Applications & Service Principals (permissions, credentials, multi-tenant)
- Conditional Access Policies (MFA, device compliance, legacy auth blocking)
- PIM roles (permanent vs eligible assignments, approval policies)
- Audit/sign-in logs
- Risk detections (compromised credentials, anomalous sign-ins)

---

## One binary, one license

Since v3.2.0 there is no Community/Pro split — every detection below ships
in the single published binary, under the
[Functional Source License 1.1, Apache 2.0 Future License](../LICENSING.md)
(free to use, modify, self-host and run in production, including commercial
use; converts to plain Apache 2.0 two years after each release).

| | Included |
|---|-----|
| AD — 14 categories (346 detections) | ✅ |
| Azure — 9 categories (161 detections) | ✅ |
| ADCS — ESC1–ESC11 | ✅ |
| Attack Paths — privilege graph | ✅ |
| Azure Risk Protection | ✅ |
| REST API & embedded GUI | ✅ |
| JSON export | ✅ |
| Compliance (9 frameworks: ANSSI, HDS, RGPD, NIS2, CIS, NIST, DISA STIG) | ✅ |
| **Total detections** | **507** |
| **Source** | Source-available on GitHub |
| **Access** | Direct download |

---

## Risk Scoring

Every audit produces a **risk score** (0–100, where 100 = no risk) and a **rating** (A–F):

| Rating | Score | Meaning |
|--------|-------|---------|
| A | 80–100 | Excellent — minimal risk |
| B | 60–79 | Good — minor improvements needed |
| C | 40–59 | Moderate — significant issues |
| D | 20–39 | Poor — serious exposure |
| F | 0–19 | Critical — likely compromised |

The score is weighted by severity and entity type (privileged accounts carry more weight):

| Severity | Weight |
|----------|--------|
| Critical | 10 |
| High | 3 |
| Medium | 1 |
| Low | 0.2 |
| Info | 0 |

---

## Optional: Network Probes

Activate with `--enable-network-probes` to add:
- **ADCS ESC8** — HTTP endpoint exposure of the CA enrollment service
- **DNS zone transfer (AXFR)** — tests if DNS allows unauthorized zone dumps
- **LDAP signing** — verifies domain controller LDAP signing requirements
- **SMB signing** — verifies domain controller SMB signing requirements

Network probes add ~1–2 seconds and require additional network access from the collector host.

---

## Output Format

All results are returned as structured JSON, consumable by:
- SIEM platforms (Splunk, Elastic, Sentinel)
- Vulnerability management tools
- Custom dashboards
- The embedded web GUI

Each finding includes:
```json
{
  "type": "ASREP_ROASTING_RISK",
  "severity": "critical",
  "category": "kerberos",
  "title": "AS-REP Roasting Risk",
  "description": "User accounts without Kerberos pre-authentication...",
  "count": 25,
  "affectedEntities": [
    { "name": "svc-backup", "type": "user", "details": { ... } }
  ]
}
```

---

## See Also

- [Active Directory — full detection list](active-directory.md)
- [Azure Entra ID — full detection list](azure-entra-id.md)
- [Vulnerability Catalog](../vulnerabilities/README.md)
