# Tier 0 customization — `tier0_groups.yaml`

Optional configuration that lets a customer extend ETC's Tier 0 detection
beyond the hardcoded ANSSI defaults. Used by ANSSI compliance detectors
when the organisation's privileged groups, OUs, management systems, or
admin forest don't follow the standard naming conventions.

## Path

`<configDir>/tier0_groups.yaml`

Default `<configDir>` per platform :

| OS | Path |
|---|---|
| Linux | `/etc/etc-collector/tier0_groups.yaml` |
| macOS | `/etc/etc-collector/tier0_groups.yaml` |
| Windows | `C:\ProgramData\ETCSec\etc-collector\tier0_groups.yaml` |

## Loading behaviour

| File state | Result |
|---|---|
| Absent | Silently ignored. ANSSI detectors fall back to the hardcoded defaults (12 well-known group names + `OU=tier0`/`OU=admin`/... markers). |
| Present, valid YAML | Loaded once at the start of each `audit ad` run. Available to detectors via `DetectorData.Tier0Config`. |
| Present, malformed YAML | Warning printed to stderr (`warning: failed to load tier0_groups.yaml ...`), audit continues with defaults. **Audit run is NEVER aborted on YAML errors.** |
| Unknown YAML key | Silently ignored (Go's `yaml.v3` Unmarshal default). |

## Schema

All four top-level keys are optional. Each accepts a list of strings.

```yaml
# Tier 0 admin groups — DNs added to the recursive Tier 0 expansion on top
# of the hardcoded ANSSI default list (Domain Admins, Enterprise Admins,
# Schema Admins, Administrators, Account/Backup/Server/Print Operators,
# Protected Users, Key Admins, Enterprise Key Admins, DnsAdmins).
groups:
  - "CN=Acme-DA,OU=AcmeAdmins,DC=corp,DC=local"
  - "CN=ESAE-Admins,OU=Tier0,DC=admin,DC=corp,DC=local"

# Tier 0 OUs — DNs treated as Tier 0 containers by ANSSI R59
# (security policies on Tier 0 OU). Adds to the hardcoded markers
# (ou=tier0, ou=tier-0, ou=t0, ou=paw, ou=tier 0, ou=tier_0).
ous:
  - "OU=AcmeT0,DC=corp,DC=local"
  - "OU=PrivilegedAccess,DC=corp,DC=local"

# Centralized management systems — Computer DNs that ANSSI R49+R50 should
# NOT flag as miscategorised, even when their hostname doesn't match the
# default markers (sccm, configmgr, wsus, defender, mecm, intune, jamf,
# ansible, salt, puppet, chef, tanium, bigfix, crowdstrike, carbonblack,
# sentinelone). Use this when the customer named their SCCM "ACME-CFG01"
# (no recognizable substring).
mgmt_systems:
  - "CN=ACME-CFG01,OU=Servers,DC=corp,DC=local"
  - "CN=ACME-PATCH02,OU=Mgmt,DC=corp,DC=local"

# Admin-forest DNS suffixes — used by ANSSI R86 (admin forest segregation).
# A trust whose target domain name CONTAINS any of these strings is treated
# as an administration forest. Adds to the hardcoded markers (admin, esae,
# red, paw, tier0, t0).
admin_forest_dns:
  - "esae.corp"
  - "tier0.acmeadmin.com"
```

## Detectors that consume this config

| Detector | Field used |
|---|---|
| `ANSSI_R40_NO_PSO_TIER0` | `groups` (recursive Tier 0 member set for PSO coverage) |
| `ANSSI_R69_TIER0_SPN_EXPOSED` | `groups` (recursive Tier 0 member set for SPN check) |
| `ANSSI_R49_R50_MGMT_CATEGORIZATION` | `mgmt_systems` (whitelist — these computers are NOT flagged) |
| `ANSSI_R59_TIER0_OU_POLICIES` | `ous` (extra Tier 0 OU markers) |
| `ANSSI_R86_ADMIN_FOREST_SEGREGATION` | `admin_forest_dns` (extra admin-forest DNS suffixes) |

## Validation example

A complete file ready to drop on a Linux collector :

```yaml
groups:
  - "CN=Acme-DA,OU=AcmeAdmins,DC=corp,DC=local"
ous:
  - "OU=Tier0,DC=corp,DC=local"
mgmt_systems:
  - "CN=ACME-CFG01,OU=Servers,DC=corp,DC=local"
admin_forest_dns:
  - "esae.corp"
```

After dropping the file, the next `audit ad` run picks it up. To verify it
was loaded, look for the following pattern in the audit logs (warn level if
something failed) :

```
warning: failed to load tier0_groups.yaml (parse /etc/etc-collector/tier0_groups.yaml: yaml: line N: ...) — falling back to defaults
```

Absence of any warning = file was either absent or loaded successfully.

## When to set up this file

- Customer's Tier 0 admin groups follow custom naming (`AcmeDomainAdmins`
  instead of `Domain Admins`)
- Customer's Tier 0 OU is named `OU=PrivilegedAccess` (not `OU=Tier0`)
- Customer has a dedicated SCCM/Defender server with custom hostname
- Customer operates an ESAE / red forest with non-standard domain DNS

If the customer follows ANSSI default conventions, the file is unnecessary —
ETC's hardcoded defaults already detect everything correctly.

## Source code

- Loader: [`internal/audit/tier0_config.go`](https://github.com/etcsec-com/etc-collector-com/blob/main/internal/audit/tier0_config.go)
- Detector consumers: [`internal/audit/detectors/ad/compliance/anssi/`](https://github.com/etcsec-com/etc-collector-com/tree/main/internal/audit/detectors/ad/compliance/anssi)
