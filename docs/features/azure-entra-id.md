# Azure Entra ID Audit

ETC Collector performs **161 security detections** across **9 categories** on Azure Entra ID (formerly Azure AD) environments, using the Microsoft Graph API. All ship in the single published binary — no edition gating since v3.2.0.

---

## Summary by Category

Confirmed live 2026-09-02 against `AZURE_VULNERABILITY_CATALOG.md`, regenerated with `make catalog`:

| Category | Detections | Notes |
|----------|-----------|-------|
| Identity | 29 | Authentication methods, MFA, password policy, hybrid sync health |
| Applications | 28 | App registrations, service principals, CBA persistence, SAML cert health |
| Conditional Access | 20 | CA policies, MFA enforcement, legacy auth |
| Privileged Access | 24 | PIM, permanent assignments, role thresholds, unresolved members |
| Guest & External | 15 | Guest users, B2B access, invitation policies |
| Config | 8 | Security defaults, diagnostics, tenant settings |
| Groups | 12 | Dynamic groups, privileged memberships, ownership |
| Compliance | 8 | Licensing, access reviews, identity protection |
| Risk Protection | 17 | Anomaly detection, risk-based policies |
| **Total** | **161** | |

---

## Data Collection

ETC calls **Microsoft Graph API** endpoints using an app registration with Application permissions (not delegated). No changes are made to the tenant.

The app authenticates with **either a client secret or a client certificate**
(`client_assertion`). Tenants that forbid client-secret creation — frequent in
regulated and public-sector environments — use the certificate path: see
[Certificate Authentication](../configuration/permissions.md#certificate-authentication-recommended).

**Endpoints used:**
- `/users` — user profiles, MFA status, risk level, password age
- `/groups` — group membership, dynamic rules, owners
- `/applications` + `/servicePrincipals` — app registrations and permissions
- `/identity/conditionalAccess/policies` — CA policy configuration
- `/roleManagement/directory` — role assignments (permanent + eligible)
- `/policies/authorizationPolicy` — tenant-wide settings
- `/auditLogs/signIns` — sign-in risk events
- `/identityProtection` — user risk, sign-in risk
- `/privilegedAccess/aadRoles` — PIM policies and assignments

**Audit time:** 8–30 seconds depending on tenant size and API throttling.

---

## Categories in Detail

### Identity (29 detections)

Covers authentication methods, legacy protocols, password policy, and hybrid sync health.

**Critical/High:**
- `LEGACY_AUTH_NOT_BLOCKED` — Basic auth / legacy protocols not blocked by CA policy (primary attack vector for password spraying)
- `MFA_NOT_ENFORCED_ALL_USERS` — No CA policy requiring MFA for all users
- `MFA_NOT_ENFORCED_ADMINS` — Admins without MFA requirement
- `MFA_SUSPICIOUS_ACTIVITY` — Identity Protection signals correlate on the same user (multi-IP, multi-geo, high-risk events)
- `SMS_VOICE_MFA_USED` — SMS/voice OTP as MFA method (SIM-swapping vulnerable)
- `EMAIL_OTP_MFA` — Email OTP as MFA method (account takeover risk)
- `WEAK_PASSWORD_POLICY` — Tenant doesn't enforce strong password requirements
- `PASSWORD_PROTECTION_NOT_DEPLOYED` — Azure AD Password Protection absent (custom banned list)
- `SSPR_NOT_ENABLED` — Self-Service Password Reset disabled (support burden + security gap)
- `SSPR_WEAK_AUTHENTICATION` — SSPR uses weak authentication methods

**Medium:**
- `AUTH_METHOD_REGISTRATION_POLICY_NOT_SET` — No combined registration policy
- `PASSWORDLESS_NOT_ENABLED` — Passwordless methods (FIDO2, Windows Hello) not deployed
- `STALE_USER_ACCOUNTS` — Users inactive 90+ days with enabled accounts
- `GUEST_MFA_NOT_REQUIRED` — Guest users can authenticate without MFA
- `MFA_UNUSUAL_LOCATION` — Risky sign-ins from geographies outside Named Locations
- `HYBRID_ORPHANED_CLOUD_USER` — Cloud user marked as on-prem synced but disabled (stale sync artifact)
- `HYBRID_CLOUD_ONLY_PRIVILEGED` — Cloud-only user holds a privileged role in a hybrid tenant

---

### Applications (28 detections)

App registrations and service principals with dangerous permissions, persistent certificates, or expiring SAML signing keys.

**Critical/High:**
- `APP_ADMIN_CONSENT_NOT_REQUIRED` — Users can consent to any app permission (OAuth phishing)
- `APP_DANGEROUS_PERMISSION_DIRECTORY` — `Directory.ReadWrite.All` granted (full directory access)
- `APP_DANGEROUS_PERMISSION_MAIL` — `Mail.ReadWrite` / `Mail.Send` — exfiltration risk
- `APP_DANGEROUS_PERMISSION_ROLE_MANAGEMENT` — `RoleManagement.ReadWrite.All` — can assign Global Admin
- `APP_DANGEROUS_PERMISSION_FILES` — `Files.ReadWrite.All` — all SharePoint/OneDrive files
- `APP_IMPLICIT_GRANT_ID_TOKEN` — Implicit grant with ID token (legacy, CSRF-vulnerable)
- `APP_MULTI_TENANT` — Multi-tenant apps without consent controls
- `APP_SECRET_EXPIRING` — Application secrets expiring within 30 days
- `APP_SECRET_EXPIRED` — Expired application credentials still configured
- `APP_SECRET_LONG_LIVED` — Secrets/certificates valid > 2 years
- `SERVICE_PRINCIPAL_HIGH_PRIVILEGE` — Service principal assigned Global Admin or equivalent
- `APP_NO_OWNER` — Application registration with no owner (orphaned)
- `APP_HIGH_PRIVILEGE_NO_MFA` — High-privilege service principal using password credentials
- `CBA_CERTIFICATES_ACTIVE` — Active certificate-based authentication on app or SP (persistence vector surviving password resets)
- `SAML_CERTIFICATE_EXPIRED` — Expired SAML SSO token-signing certificate (federated sign-in broken)
- `SAML_CERTIFICATE_EXPIRING_SOON` — SAML signing certificate expiring within 30 days
- `SAML_CERTIFICATE_LONG_LIFETIME` — SAML signing certificate valid > 2 years

---

### Conditional Access (20 detections)

CA policies are the primary control plane for Azure identity security.

**Critical/High:**
- `CA_NO_MFA_ALL_USERS` — No policy requiring MFA for all users
- `CA_NO_MFA_ADMINS` — No policy requiring MFA specifically for admin roles
- `CA_LEGACY_AUTH_NOT_BLOCKED` — Legacy auth protocols not explicitly blocked
- `CA_NO_DEVICE_COMPLIANCE` — No device compliance requirement for sensitive resources
- `CA_NO_RISK_BASED_POLICY` — No sign-in or user risk conditional access
- `CA_TOKEN_PROTECTION_ABSENT` — No token protection / binding policy
- `CA_BREAK_GLASS_EXCLUDED_INCORRECTLY` — Break-glass accounts excluded from too many policies
- `CA_GUEST_NO_MFA` — Guest users not subject to MFA via CA

**Medium:**
- `CA_NAMED_LOCATION_NOT_USED` — No trusted location defined
- `CA_SESSION_LIFETIME_TOO_LONG` — Session persistence > 8 hours without re-auth
- `CA_PLATFORM_FILTERING_ABSENT` — No platform-based controls (iOS, Android)
- `CA_REPORT_ONLY_POLICIES` — Policies in report-only mode (not enforcing)
- `CA_WIDE_EXCLUSIONS` — CA policies with large user/group exclusions

---

### Privileged Access (24 detections)

PIM configuration, permanent privileged role assignments, and per-role count thresholds.

**Critical/High:**
- `PIM_NOT_CONFIGURED` — No PIM (Privileged Identity Management) deployed
- `GLOBAL_ADMIN_COUNT_HIGH` — More than 5 Global Administrators (attack surface)
- `PA_TOO_MANY_PRIVILEGED_ROLE_ADMINS` — More than 3 Privileged Role Administrators (can grant any role)
- `PA_TOO_MANY_SECURITY_ADMINS` — More than 3 Security Administrators
- `PA_TOO_MANY_EXCHANGE_ADMINS` — More than 3 Exchange Administrators
- `PA_TOO_MANY_SHAREPOINT_ADMINS` — More than 3 SharePoint Administrators
- `PA_TOO_MANY_APP_ADMINS` — More than 5 Application Administrators
- `PERMANENT_GLOBAL_ADMIN` — Global Admin assigned permanently (not just eligible via PIM)
- `PERMANENT_PRIVILEGED_ROLE` — Any privileged role assigned permanently without PIM
- `NO_EMERGENCY_ACCESS_ACCOUNT` — No break-glass account configured
- `EMERGENCY_ACCOUNT_IN_PIM` — Emergency account is eligible (not permanent — defeats purpose)
- `PIM_NO_APPROVAL_REQUIRED` — PIM activation doesn't require approval for sensitive roles
- `PIM_NO_JUSTIFICATION_REQUIRED` — PIM activation without justification requirement
- `PIM_ACTIVATION_TOO_LONG` — PIM activation duration > 8 hours
- `PIM_NO_MFA_ON_ACTIVATION` — PIM doesn't require MFA re-authentication to activate role
- `SERVICE_PRINCIPAL_GLOBAL_ADMIN` — Service principal with Global Admin role
- `PRIVILEGED_ROLE_EXTERNAL_MEMBER` — Guest/external user in privileged role
- `UNRESOLVED_PRIVILEGED_MEMBERS` — Privileged role assignment references a principal whose object can't be resolved (stale / deleted user)

---

### Guest & External (15 detections)

Guest users and B2B collaboration settings.

**High:**
- `GUEST_IN_PRIVILEGED_ROLE` — Guest user assigned admin role
- `GUEST_INVITATION_UNRESTRICTED` — Any member can invite guests
- `GUEST_CROSS_TENANT_SYNC` — Cross-tenant synchronization without restrictions
- `GUEST_B2B_UNRESTRICTED` — No cross-tenant access restrictions
- `STALE_GUEST_ACCOUNTS` — Guest accounts inactive 90+ days
- `GUEST_DIRECTORY_VISIBLE` — Guests can enumerate all directory objects
- `GUEST_ALLOWED_TO_REGISTER_APPS` — Guests can create app registrations

**Medium:**
- `EXTERNAL_COLLABORATION_UNRESTRICTED` — No restrictions on external collaboration domains
- `GUEST_MFA_NOT_REQUIRED` — No MFA requirement for guest authentication
- `GUEST_IN_SECURITY_GROUP` — Guests in security groups with sensitive access

---

### Config (8 detections)

Tenant-level settings and security defaults.

**High:**
- `SECURITY_DEFAULTS_DISABLED` — Azure Security Defaults turned off without CA replacement
- `DIAGNOSTIC_SETTINGS_ABSENT` — No audit log export configured (no SIEM integration)
- `AUDIT_LOG_RETENTION_SHORT` — Log retention < 90 days
- `USER_CONSENT_UNRESTRICTED` — Users can consent to OAuth apps without admin approval
- `APP_REGISTRATION_UNRESTRICTED` — Any user can create app registrations
- `SELF_SERVICE_GROUP_CREATION` — Any user can create security groups
- `LINKEDIN_SYNC_ENABLED` — LinkedIn account sync (data leakage)

**Medium:**
- `TERMS_OF_USE_ABSENT` — No Terms of Use policy configured
- `PRIVACY_STATEMENT_ABSENT` — No privacy statement linked
- `HYBRID_IDENTITY_WEAK_SYNC` — Azure AD Connect sync without password hash sync

---

### Groups (12 detections)

Azure AD group configuration and privileged memberships.

**High:**
- `DYNAMIC_GROUP_SUSPICIOUS_RULE` — Dynamic membership rule includes external domains or insecure attributes
- `ROLE_ASSIGNABLE_GROUP_UNMONITORED` — Role-assignable group without proper ownership
- `PRIVILEGED_GROUP_LARGE` — Global Admin or equivalent group with > 5 members
- `NESTED_PRIVILEGED_GROUPS` — Nested group membership grants hidden privilege

**Medium:**
- `GROUP_NO_OWNER` — Security group without an owner
- `GUEST_IN_SECURITY_GROUP` — Guest user in security group (potential overpermission)
- `GROUP_OWNER_EXTERNAL` — Group owned by guest/external user
- `LARGE_GROUP_UNMONITORED` — Groups with 500+ members and no ownership policy

---

### Compliance (8 detections)

Licensing and access governance.

**High:**
- `P2_LICENSE_ABSENT` — No Entra ID P2 / Microsoft 365 E5 license (required for PIM, Identity Protection)
- `ACCESS_REVIEWS_NOT_CONFIGURED` — No periodic access reviews (violates least-privilege principle)
- `IDENTITY_PROTECTION_NOT_LICENSED` — Identity Protection features unavailable

**Medium:**
- `PRIVILEGED_ACCESS_WORKBOOK_ABSENT` — No workbook monitoring privileged role usage
- `ENTITLEMENT_MANAGEMENT_UNUSED` — Access packages not used for governed access
- `CIS_BENCHMARK_GAP` — Specific CIS Microsoft 365 benchmark controls not met

---

### Risk Protection (17 detections)

Automated detection of anomalous identity behavior.

**Critical/High:**
- `RISKY_USER_NOT_REMEDIATED` — User with high risk level not addressed
- `SIGN_IN_RISK_POLICY_ABSENT` — No automated response to risky sign-ins
- `USER_RISK_POLICY_ABSENT` — No automated response to high-risk users
- `COMPROMISED_CREDENTIALS_DETECTED` — Microsoft-detected leaked credentials
- `ANOMALOUS_TOKEN_DETECTED` — Unusual token characteristics (token theft indicators)

**Medium:**
- `BULK_DOWNLOAD_DETECTED` — Anomalous data download patterns
- `IMPOSSIBLE_TRAVEL_NOT_BLOCKED` — No policy blocking impossible travel sign-ins
- `UNFAMILIAR_SIGN_IN_PROPERTIES` — Sign-ins from unfamiliar locations not flagged

---

## Required Permissions

| Permission | Type | Purpose |
|-----------|------|---------|
| `Directory.Read.All` | Application | Users, groups, org details |
| `User.Read.All` | Application | Full user profiles |
| `Group.Read.All` | Application | Groups and membership |
| `Application.Read.All` | Application | Apps and service principals |
| `RoleManagement.Read.All` | Application | Role assignments |
| `RoleManagementPolicy.Read.Directory` | Application | PIM policies |
| `Policy.Read.All` | Application | Conditional Access |
| `AuditLog.Read.All` | Application | Sign-in logs |
| `IdentityRiskyUser.Read.All` | Application | Risk detections |

All permissions are **Application** type (not Delegated) — the collector runs unattended without user interaction.

---

## See Also

- [Full Azure Vulnerability Catalog](../vulnerabilities/azure/AZURE_VULNERABILITY_CATALOG.md)
- [Required Permissions — setup guide](../configuration/permissions.md#azure-entra-id)
- CLI: `etc-collector audit azure --help`
