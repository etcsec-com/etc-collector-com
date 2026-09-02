# Active Directory Audit

ETC Collector performs **346 security detections** across **14 categories** on Active Directory environments, connecting via LDAP/LDAPS and SMB (SYSVOL). All ship in the single published binary — no edition gating since v3.2.0.

---

## Summary by Category

Confirmed live 2026-09-02 against `AD_VULNERABILITY_CATALOG.md`, regenerated with `make catalog`:

| Category | Detections | Critical | High | Medium | Low | Info |
|----------|-----------|---------|------|--------|-----|------|
| Password | 10 | 4 | 2 | 4 | 0 | 0 |
| Kerberos | 14 | 5 | 4 | 4 | 1 | 0 |
| Accounts | 32 | 3 | 14 | 12 | 2 | 1 |
| Groups | 17 | 1 | 7 | 8 | 0 | 1 |
| Computers | 34 | 10 | 9 | 8 | 4 | 3 |
| Advanced | 49 | 8 | 9 | 19 | 4 | 9 |
| Permissions | 23 | 3 | 10 | 9 | 0 | 1 |
| ADCS | 11 | 3 | 6 | 2 | 0 | 0 |
| GPO | 35 | 6 | 9 | 15 | 4 | 1 |
| Trusts | 7 | 0 | 4 | 3 | 0 | 0 |
| Attack Paths | 3 | 2 | 1 | 0 | 0 | 0 |
| Monitoring | 8 | 0 | 4 | 3 | 1 | 0 |
| Compliance | 88 | 3 | 36 | 35 | 8 | 6 |
| Network | 15 | 0 | 7 | 2 | 3 | 3 |
| **Total** | **346** | **48** | **122** | **124** | **27** | **25** |

---

## Data Collection

ETC connects over **LDAP/LDAPS** (port 389/636) and **SMB** (port 445 for SYSVOL) with a read-only service account. No changes are made to the directory.

**Objects collected:**
- Users, groups, computers (all attributes including UAC flags, msDS-* attributes, SPN, SID history)
- Group Policy Objects (SYSVOL + LDAP metadata)
- Domain/forest trusts
- AD CS objects (certificate templates, CAs, PKI container)
- ACLs (nTSecurityDescriptor on every object)
- Domain information (functional level, password policy, Kerberos policy)

**Pagination:** 1,000 objects per LDAP page (configurable). On a 546-user / 100-computer domain: **6.58 seconds** total audit time including network probes.

---

## Categories in Detail

### Password (10 detections)

Detects insecure password configurations at the account level.

**Critical:**
- `PASSWORD_NOT_REQUIRED` — UAC flag 0x20: accounts that authenticate without a password
- `REVERSIBLE_ENCRYPTION` — UAC flag 0x80: passwords stored reversibly (equivalent to cleartext)
- `PASSWORD_NEVER_EXPIRES` — UAC flag 0x10000: stale credentials increase breach risk
- `PASSWORD_CLEARTEXT_STORAGE` — attributes (userPassword, unixUserPassword) contain cleartext
- `UNIX_USER_PASSWORD` — Unix password attributes with weakly-hashed or cleartext values

**High:**
- `PASSWORD_IN_DESCRIPTION` — cleartext passwords found in the description field
- `PASSWORD_COMMON_PATTERNS` — account names suggesting default passwords (admin, test, temp)

**Medium:**
- `PASSWORD_VERY_OLD` — passwords older than 365 days
- `USER_CANNOT_CHANGE_PASSWORD` — UAC flag 0x40: prevents rotation
- `PASSWORD_DICT_ATTACK_RISK` — repeated bad password attempts / lockout patterns

---

### Kerberos (14 detections)

Detects Kerberos misconfigurations enabling ticket attacks and delegation abuse.

**Critical:**
- `ADMIN_ASREP_ROASTABLE` — Domain/Enterprise Admins without pre-auth (immediate domain compromise risk)
- `ASREP_ROASTING_RISK` — Any user without Kerberos pre-auth (UAC 0x400000)
- `GOLDEN_TICKET_RISK` — krbtgt password unchanged 180+ days
- `UNCONSTRAINED_DELEGATION` — Accounts with unconstrained delegation (UAC 0x80000), can impersonate any user

**High:**
- `KERBEROASTING_RISK` — Accounts with SPNs (service account password cracking)
- `CONSTRAINED_DELEGATION` — Accounts with constrained delegation, can impersonate users to specific services
- `KERBEROS_AES_DISABLED` — Forces fallback to weaker DES/RC4
- `WEAK_ENCRYPTION_DES` — DES encryption enabled (cryptographically broken)
- `DELEGATION_UNKNOWN_TARGET` — Delegation to SPNs with no matching computer in AD

**Medium/Low:**
- `KERBEROS_RC4_FALLBACK`, `WEAK_ENCRYPTION_FLAG`, `WEAK_ENCRYPTION_RC4` — downgrade attack vectors
- `KERBEROS_TICKET_LIFETIME_LONG` — TGT > 10 hours widens attack window
- `KERBEROS_RENEWABLE_TICKET_LONG` — Renewable lifetime > 7 days

---

### Accounts (32 detections)

The largest category — covers privileged accounts, service accounts, and general hygiene.

**Critical:**
- `SENSITIVE_DELEGATION` — Domain/Enterprise Admins with any delegation
- `SID_HISTORY_ABUSE` — SID history on accounts that don't need it (privilege escalation)
- `SHADOW_CREDENTIALS` — msDS-KeyCredentialLink on accounts (PKINIT backdoor)

**High (examples):**
- `PRIVILEGED_ACCOUNT_STALE` — Admin accounts inactive 90+ days (53 found on test domain)
- `ADMIN_WITHOUT_SMARTCARD` — Privileged accounts without certificate-based auth requirement
- `SERVICE_ACCOUNT_PRIVILEGED` — Service accounts with direct DA/EA membership
- `SERVICE_ACCOUNT_INTERACTIVE_LOGON` — Service accounts allowed to log on interactively
- `ADMIN_NOT_IN_PROTECTED_USERS` — Privileged accounts outside the Protected Users security group
- `FOREIGN_SECURITY_PRINCIPAL` — FSPs from external/untrusted domains in sensitive groups
- `ACCOUNT_OPERATORS_MEMBERS` — Non-empty Account Operators group (can manipulate AD objects)

**Medium/Low (examples):**
- `STALE_ACCOUNTS` — Accounts not used in 90+ days still enabled
- `TEST_SHARED_ACCOUNTS` — Accounts whose names suggest shared/test use
- `EXPIRED_ACCOUNTS_IN_PRIVILEGED_GROUPS` — Expired accounts still in privileged groups

---

### Groups (17 detections)

Analyses group membership and delegation for privilege creep.

**Critical:**
- `EVERYONE_IN_PRIVILEGED_GROUP` — "Everyone" or "Authenticated Users" in sensitive groups

**High:**
- `DNS_ADMINS_ABUSE` — Non-empty DnsAdmins (can load malicious DLL on DC)
- `GPO_CREATORS_OWNER_MEMBERSHIP` — Non-default members can create domain-wide GPOs
- `BACKUP_OPERATORS_MEMBERS` — Members can read any file including NTDS.dit
- `SCHEMA_ADMINS_MEMBERS` — Active Schema Admins members
- `EXCHANGE_ELEVATED_PERMISSIONS` — Exchange groups with unnecessary AD rights
- `GMSA_PASSWORD_READERS` — Non-privileged principals that can read a gMSA password (Purple Knight SI000083 parity)

**Medium/Low:**
- `LARGE_PRIVILEGED_GROUP` — DA/EA groups with > 5 members
- `DEEPLY_NESTED_GROUPS` — High nesting depth obscures effective permissions
- `UNMONITORED_PRIVILEGED_GROUP` — Groups with admin rights but no monitoring flag
- `NON_PROTECTED_USERS_MEMBERS` — Privileged users not in Protected Users group

---

### Computers (34 detections)

Covers workstations and servers: OS age, security settings, delegation.

**Critical:**
- `LAPS_NOT_DEPLOYED` — Local admin password solution absent (lateral movement risk)
- `COMPUTER_UNCONSTRAINED_DELEGATION` — Computers with unconstrained delegation
- `OS_WINDOWS_XP_2003` — End-of-life OS with known critical vulnerabilities
- `OS_WINDOWS_VISTA_2008` — End-of-life OS
- `OS_WINDOWS_7_2008R2` — End-of-life OS
- `COMPUTER_IN_ADMIN_GROUP` — Computer accounts in DA/EA groups
- `COMPUTER_RBCD_ABUSE` — Computer has AllowedToActOnBehalfOfOtherIdentity set (RBCD)
- `BITLOCKER_NOT_ENABLED` — Disk encryption absent
- `RODC_PRIVILEGED_CACHING` — RODC caches credentials of privileged principals via msDS-RevealedList (Purple Knight SI000022 parity)

**High:**
- `LAPS_DOMAIN_COVERAGE_LOW` — < 80% of computers have LAPS
- `COMPUTER_PASSWORD_VERY_OLD` — Machine account password > 60 days (default: 30 days)
- `COMPUTER_CONSTRAINED_DELEGATION` — Constrained delegation on computers

---

### Advanced (49 detections)

The broadest category — covers domain-level security and attack enablers.

**Critical (examples):**
- `SHADOW_CREDENTIALS_COMPUTER` — msDS-KeyCredentialLink on computer accounts
- `RBCD_ABUSE` — Resource-Based Constrained Delegation misconfiguration
- `LDAP_SIGNING_DISABLED` — DC doesn't require LDAP signing (LDAP relay risk)
- `SMB_SIGNING_DISABLED` — DC doesn't require SMB signing (relay attacks)
- `DCSYNC_CAPABLE` — Non-DC accounts with GetChangesAll/GetChanges ACEs
- `MACHINE_ACCOUNT_QUOTA_ABUSE` — Default quota of 10 allows any user to add computer accounts
- `ADMIN_SD_HOLDER_MODIFIED` — AdminSDHolder ACL modified (persists to all protected objects)
- `REPLICATION_RIGHTS` — Excessive replication rights outside normal DCs

**High (examples):**
- `DANGEROUS_LOGON_SCRIPTS` — Logon scripts with potentially dangerous commands
- `LAPS_COVERAGE_BY_OU` — OUs without LAPS coverage
- `FOREIGN_SECURITY_PRINCIPALS` — FSPs from untrusted forests

---

### Permissions (23 detections)

ACL-level analysis — finds accounts that can modify, own, or compromise other objects.

**Critical:**
- `DANGEROUS_ACL_GENERICALL` — GenericAll on sensitive objects (full control)

**High (examples):**
- `DANGEROUS_ACL_WRITEDACL` — WriteDACL allows granting arbitrary permissions
- `DANGEROUS_ACL_WRITEOWNER` — WriteOwner allows taking ownership
- `DANGEROUS_ACL_WRITESPN` — WriteSPN enables Kerberoasting targeting
- `DANGEROUS_ACL_SELF_MEMBERSHIP` — Self-membership write enables privilege escalation
- `REPLICATION_RIGHTS_NON_DC` — Non-DC with replication rights (DCSync)

On the test domain example.com: **~6,240 ACL instances** analyzed across all objects.

---

### ADCS — Active Directory Certificate Services

11 detections covering the full ESC1–ESC11 vulnerability taxonomy.

| Detection | Severity | Description |
|-----------|----------|-------------|
| `ESC1_VULNERABLE_TEMPLATE` | Critical | Template allows SAN specification + low-privilege enrollment |
| `ESC2_ANY_PURPOSE` | High | "Any Purpose" or "Subordinate CA" EKU + low-privilege enrollment |
| `ESC3_ENROLLMENT_AGENT` | High | Enrollment Agent EKU enables impersonation |
| `ESC4_VULNERABLE_TEMPLATE_ACL` | Critical | Template ACL allows modification by non-admins |
| `ESC5_VULNERABLE_PKI_OBJECT_ACL` | Critical | CA object ACL misconfiguration |
| `ESC6_EDITF_ATTRIBUTESUBJECTALTNAME2` | High | CA flag enables SAN on any request |
| `ESC7_VULNERABLE_CA_ACL` | High | CA ACL allows template/config modification |
| `ESC8_HTTP_ENDPOINT_EXPOSED` | High | ADCS HTTP enrollment endpoint (NTLM relay target) |
| `ESC9_NO_SECURITY_EXTENSION` | Medium | Missing szOID_NTDS_CA_SECURITY_EXT |
| `ESC10_WEAK_CERTIFICATE_MAPPINGS` | High | Weak certificate-to-account mapping |
| `ESC11_ICPR_HTTP` | High | ICertPassage over HTTP (relay risk) |

On example.com: **22 ADCS instances** found (ESC1×1, ESC2×3, ESC3×4, ESC4×12, ESC6, ESC10, ESC11).

---

### GPO — Group Policy Objects (35 detections)

Covers policy security settings, permissions, and dangerous configurations.

**Critical (examples):**
- `GPO_DANGEROUS_SCRIPTS` — Startup/shutdown/logon scripts with suspicious commands
- `GPO_WEAK_PASSWORD_POLICY` — Password policy weaker than minimum baseline
- `GPO_ADMIN_TEMPLATE_DANGEROUS` — ADMX templates enabling dangerous settings
- `GPO_SEENABLETOKENPRIV` — SeEnableDelegationPrivilege granted via GPO

**High:**
- `GPO_UNLINKED` — GPOs created but never linked (administrative overhead risk)
- `GPO_MODIFIED_BY_NON_ADMIN` — GPO recently modified by non-administrator account
- `GPO_OVERPERMISSIONED` — Wide write access on GPO objects

---

### Trusts (7 detections)

Forest/domain trust configuration analysis.

**High (examples):**
- `TRUST_SID_FILTERING_DISABLED` — SID filtering off = SID injection across trusts
- `TRUST_UNCONSTRAINED_TRANSITIVE` — External transitive trusts with no SID filtering
- `TRUST_FOREST_BIDIRECTIONAL` — Bidirectional forest trust (full privilege path)
- `TRUST_EXTERNAL_WITHOUT_FILTERING` — External trust without quarantine

---

### Attack Paths (3 detections)

Graph-based analysis identifying complete privilege escalation chains from any authenticated user to Domain Admin or Domain Controller.

**Critical:**
- `PATH_SERVICE_TO_DA` — Service account → Domain Admin escalation paths (22 found on example.com)
- `PATH_ACL_ABUSE` — ACL chain from unprivileged user to sensitive target

**High:**
- `PATH_NESTED_ADMIN` — Nested group membership creating hidden admin paths (5 found on example.com)

**Attack graph statistics on example.com:**
- 65 exploitable paths identified (107 candidates evaluated)
- 20 Critical paths, 45 High paths
- Average path length: 1.1 hops (max: 3)
- 83 distinct privileged targets identified

---

### Monitoring (8 detections)

Detects missing security monitoring infrastructure.

**High:**
- `AUDIT_POLICY_INSUFFICIENT` — Missing audit categories (logon, object access, privilege use)
- `ANONYMOUS_LDAP_ACCESS` — DC allows unauthenticated LDAP queries
- `RECYCLE_BIN_DISABLED` — AD Recycle Bin not enabled (deleted objects unrecoverable)

---

### Compliance (88 detections)

Maps findings to security frameworks.

**Coverage:**
- **CIS** (Center for Internet Security) — AD hardening benchmarks
- **NIST SP 800-53** — Federal security controls
- **ANSSI** — French national cybersecurity agency guidelines
- **DISA STIG** — US DoD Security Technical Implementation Guides

---

### Network (15 detections)

Protocol-level security checks (some require `--enable-network-probes`).

**High:**
- `LDAP_CHANNEL_BINDING_NOT_REQUIRED` — Enables LDAP relay attacks
- `SMB_V1_ENABLED` — SMBv1 active (EternalBlue, WannaCry)
- `DNS_ZONE_INSECURE_UPDATE` — DNS allows unsigned dynamic updates (spoofing/hijacking)
- `DNSSEC_NOT_ENABLED` — DNS responses not signed

---

## Performance Reference

| Domain Size | Objects | Audit Time (approx.) |
|------------|---------|---------------------|
| Small (< 1,000 users) | < 5,000 | 5–15 seconds |
| Medium (1,000–10,000) | 5,000–50,000 | 1–5 minutes |
| Large (10,000–100,000) | 50,000–500,000 | 5–20 minutes |
| Enterprise (100,000+) | 500,000+ | 20+ minutes |

*Benchmarked on example.com: 546 users, 100 computers → 6.58 seconds with network probes enabled*

---

## See Also

- [Full Vulnerability Catalog](../vulnerabilities/active-directory/AD_VULNERABILITY_CATALOG.md)
- [Required Permissions](../configuration/permissions.md#active-directory)
- CLI: `etc-collector audit ad --help`
