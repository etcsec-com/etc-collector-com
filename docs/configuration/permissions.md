# Required Permissions

ETC Collector requires **read-only** access. It never writes to or modifies your directory.

---

## Active Directory

### Minimum Requirements

The service account must be a member of **Domain Users** - this grants read access to most AD objects. For ACL-level detections (Permissions, Advanced categories), the account needs access to read the `nTSecurityDescriptor` attribute, which is also available to Domain Users by default.

**What Domain Users can read:**
- All user, group, computer, OU objects (standard attributes)
- GPO objects and links
- Domain/forest trust information
- msDS-* attributes (delegation, key credentials, etc.)
- Kerberos policy
- Password policy
- SID history
- ACLs (`nTSecurityDescriptor`) on most objects

**What may require additional rights:**
- `SYSVOL` read access - required for GPO content (granted by default to Domain Users)
- AD CS objects in `CN=Public Key Services,CN=Services,CN=Configuration,...` - readable by Domain Users

### Create the Service Account

```powershell
# Create a dedicated service account
$Password = ConvertTo-SecureString "ComplexP@ssw0rd!" -AsPlainText -Force

New-ADUser `
  -Name "svc-etcaudit" `
  -SamAccountName "svc-etcaudit" `
  -UserPrincipalName "svc-etcaudit@example.com" `
  -AccountPassword $Password `
  -Enabled $true `
  -PasswordNeverExpires $true `
  -CannotChangePassword $true `
  -Description "ETC Collector read-only service account"

# Domain Users membership is sufficient - no additional groups needed
Write-Host "Service account created. Domain Users membership is sufficient."
```

### Verify Access

```powershell
# Test LDAP bind and basic query
$cred = Get-Credential "svc-etcaudit"
Get-ADUser -Filter * -Credential $cred -ResultSetSize 5 | Select Name
```

### Security Best Practices

- Use a **dedicated** service account - never the administrator account
- Enable **password never expires** and rotate manually on a schedule
- Consider enabling **"This account is sensitive and cannot be delegated"** (prevents delegation abuse)
- Monitor the account with AD auditing for unexpected usage
- Place the account in a separate OU with stricter auditing

---

## Azure Entra ID

> New to Azure/Entra setup? [azure-getting-started.md](azure-getting-started.md) walks through this section end-to-end for an admin doing it for the first time, with a decision checklist and a troubleshooting table.

### Create an App Registration

```bash
# Using Azure CLI
az login

# Create the app registration
APP_NAME="ETC Collector"
az ad app create --display-name "$APP_NAME"

# Get the app ID
APP_ID=$(az ad app list --display-name "$APP_NAME" --query "[0].appId" -o tsv)
echo "App ID: $APP_ID"

# Create a service principal for the app
az ad sp create --id "$APP_ID"

# Create a client secret (valid 2 years)
SECRET=$(az ad app credential reset --id "$APP_ID" --years 2 --query password -o tsv)
echo "Client Secret: $SECRET"
```

### Grant Microsoft Graph Permissions

Permission IDs (GUIDs) are per-type (Application vs Delegated) and not memorable - rather than hardcoding them and risking a copy-paste of the wrong one, resolve each by name from the Microsoft Graph service principal itself:

```bash
# Microsoft Graph App ID - constant, identical on every tenant
GRAPH_ID="00000003-0000-0000-c000-000000000000"

# All 13 Application (app-only) permissions the collector tests before an
# Azure audit - see internal/providers/azure/client.go's requiredPermissions.
PERMISSIONS=(
  Directory.Read.All
  User.Read.All
  Group.Read.All
  Application.Read.All
  RoleManagement.Read.All
  RoleManagementPolicy.Read.Directory
  Policy.Read.All
  AuditLog.Read.All
  DelegatedPermissionGrant.Read.All
  CrossTenantInformation.ReadBasic.All
  IdentityRiskyUser.Read.All
  Organization.Read.All
  UserAuthenticationMethod.Read.All
)

for PERM_NAME in "${PERMISSIONS[@]}"; do
  # appRoles = Application permissions; oauth2PermissionScopes would be Delegated.
  PERM_ID=$(az ad sp show --id "$GRAPH_ID" \
    --query "appRoles[?value=='$PERM_NAME'].id" -o tsv)
  if [ -z "$PERM_ID" ]; then
    echo "ERROR: Application permission '$PERM_NAME' not found on the Graph SP" >&2
    continue
  fi
  az ad app permission add \
    --id "$APP_ID" \
    --api "$GRAPH_ID" \
    --api-permissions "${PERM_ID}=Role"
  echo "Added: $PERM_NAME"
done

# Grant admin consent (required!)
az ad app permission admin-consent --id "$APP_ID"
echo "Admin consent granted."
```

> **Admin consent is mandatory** for Application permissions. A Global Administrator must approve.

### Required Permissions Table

All 13 are **Application** (app-only) permissions - the collector never uses delegated/signed-in-user scopes. This is the exhaustive list tested by `CheckPermissions` before every `audit azure` run (`internal/providers/azure/client.go`); granting exactly these (no more) satisfies every built-in Azure detector.

| Permission | Type | Required For |
|-----------|------|-------------|
| `Directory.Read.All` | Application | General directory reads - users, groups, org info, domain info |
| `User.Read.All` | Application | Full user profiles |
| `Group.Read.All` | Application | Groups, owners, members |
| `Application.Read.All` | Application | App registrations, service principals (OAuth over-permissioning detection) |
| `RoleManagement.Read.All` | Application | Role assignments - permanent **and** PIM-eligible |
| `RoleManagementPolicy.Read.Directory` | Application | PIM policies (activation rules, required MFA, max duration) |
| `Policy.Read.All` | Application | Conditional Access, Named Locations, auth methods policy, Security Defaults |
| `AuditLog.Read.All` | Application | Sign-in logs and directory audit logs |
| `DelegatedPermissionGrant.Read.All` | Application | Existing OAuth delegated-permission grants (risky consent detection) |
| `CrossTenantInformation.ReadBasic.All` | Application | Cross-tenant access policy (B2B partners, multi-tenant org) |
| `IdentityRiskyUser.Read.All` | Application | Risky users (Identity Protection) - **requires Entra ID P2**; a `403` here with every other permission granted usually means the license is missing, not a consent problem |
| `Organization.Read.All` | Application | License/SKU info, tenant privacy statement |
| `UserAuthenticationMethod.Read.All` | Application | Per-user MFA registration and coverage report |

### Get Tenant ID

```bash
# Get your tenant ID
az account show --query tenantId -o tsv
```

### Configure the Collector

```yaml
# config.yaml
azure:
  tenantId: "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
  clientId: "yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy"
  clientSecret: "${AZURE_CLIENT_SECRET}"
```

Or via CLI:
```bash
etc-collector audit azure \
  --tenant-id "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" \
  --client-id "yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy" \
  --client-secret "your-secret"
```

Or via environment variables (`AZURE_TENANT_ID`, `AZURE_CLIENT_ID`,
`AZURE_CLIENT_SECRET`) - precedence is CLI flag > environment variable >
`config.yaml` > default, see [README.md](README.md).

### Certificate Authentication (recommended)

Instead of a client secret, the collector can authenticate with a **client
certificate** (OAuth 2.0 `client_assertion` / private-key JWT). This is the only
option in tenants that forbid the creation of client secrets - common in
regulated and public-sector environments - and it removes the yearly
secret-expiry incident.

The collector holds the **private key**; the app registration holds only the
**public certificate**.

#### 1. Generate the key pair

```bash
# Self-signed, 2 years, RSA 2048 - key + certificate in one PEM bundle
openssl req -x509 -newkey rsa:2048 -sha256 -days 730 -nodes \
  -keyout entra-key.pem -out entra-cert.pem \
  -subj "/CN=ETC Collector"

# The collector needs BOTH parts in one file
cat entra-cert.pem entra-key.pem > entra.pem
chmod 600 entra.pem
```

Windows / PowerShell:

```powershell
$cert = New-SelfSignedCertificate -Subject "CN=ETC Collector" `
  -CertStoreLocation "Cert:\CurrentUser\My" -KeyExportPolicy Exportable `
  -KeySpec Signature -NotAfter (Get-Date).AddYears(2)

# Public part -> upload to Entra
Export-Certificate -Cert $cert -FilePath entra-cert.cer

# Private part -> stays on the collector host
$pwd = ConvertTo-SecureString -String "<password>" -Force -AsPlainText
Export-PfxCertificate -Cert $cert -FilePath entra.pfx -Password $pwd
```

#### 2. Upload the public certificate to the app registration

```bash
az ad app credential reset --id "$APP_ID" --cert "@entra-cert.pem" --append
```

Portal: **Entra ID → App registrations → your app → Certificates & secrets →
Certificates → Upload certificate**, and upload `entra-cert.cer` /
`entra-cert.pem` - the **public** file only. Never upload the private key.

Permissions and admin consent are unchanged: certificate authentication only
replaces how the collector proves its identity.

#### 3. Point the collector at the private key

```bash
etc-collector audit azure \
  --tenant-id "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" \
  --client-id "yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy" \
  --client-cert /etc/etc-collector/entra.pem

# PKCS#12 / .pfx bundle
etc-collector audit azure \
  --tenant-id "..." --client-id "..." \
  --client-cert /etc/etc-collector/entra.pfx \
  --client-cert-password "<password>"
```

`--client-secret` becomes optional: provide **either** a secret **or** a
certificate. If both are configured, the certificate is used.

The same fields also work via `config.yaml` and environment variables - not
CLI-only:

```yaml
# config.yaml
azure:
  tenantId: "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
  clientId: "yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy"
  clientCertPath: "/etc/etc-collector/entra.pem"       # PEM bundle or .pfx/.p12
  # clientCertPassword: "${AZURE_CLIENT_CERT_PASSWORD}"  # only for an encrypted .pfx/.p12
```

Or inline, without a file on disk - the one field with **no CLI flag**,
because a multi-line PEM cannot be passed as a command-line argument:

```yaml
azure:
  clientCertPem: |
    -----BEGIN CERTIFICATE-----
    ...
    -----END PRIVATE KEY-----
```

```bash
export AZURE_CLIENT_CERT_PEM="$(cat entra.pem)"
```

#### Accepted formats

| Format | Extension | Password |
|--------|-----------|----------|
| PEM bundle (certificate + private key) | `.pem` | not supported (use an unencrypted key) |
| PKCS#12 | `.pfx`, `.p12` | `--client-cert-password` |

> **PKCS#12 exported by OpenSSL 3 needs `-legacy`.** OpenSSL 3 defaults to
> AES-256-CBC with a SHA-256 MAC, which the PKCS#12 reader in the Azure SDK
> cannot decrypt - the collector reports
> `parse client certificate ... unknown digest algorithm`. Re-export with
> `openssl pkcs12 -export -legacy ...`, or convert the bundle to PEM:
> ```bash
> openssl pkcs12 -in entra.pfx -out entra.pem -nodes
> ```
> `Export-PfxCertificate` on Windows produces a compatible bundle.

> **Uploading the wrong half** is the other common error: if the file you point
> `--client-cert` at contains a certificate but no private key, the collector
> says so explicitly - that file is the public part meant for Entra.

#### Rotation

Generate a new key pair, upload the new public certificate with `--append`
(both are then valid), switch `--client-cert` on the collector, then delete the
old certificate from the app registration.

### Security Best Practices

- Use **client certificates** instead of client secrets when possible (more secure, no expiry surprise) - see [Certificate Authentication](#certificate-authentication-recommended)
- Set secrets to expire in **1-2 years** and rotate before expiry
- Restrict the service principal with **Conditional Access** policies (e.g., only from the collector's IP)
- Monitor service principal sign-ins in the Entra ID audit log
- Never use `Global Administrator` - the read-only permissions above are sufficient

---

## Network Access Requirements

| Protocol | Port | Source | Destination | Purpose |
|----------|------|--------|-------------|---------|
| LDAPS | 636 | Collector | Domain Controllers | AD queries (encrypted) |
| LDAP | 389 | Collector | Domain Controllers | AD queries (cleartext / StartTLS) |
| SMB | 445 | Collector | Domain Controllers | SYSVOL / GPO files |
| HTTPS | 443 | Collector | `graph.microsoft.com` | Azure Graph API |
| HTTPS | 443 | Collector | `login.microsoftonline.com` | Azure OAuth token |
| DNS | 53 | Collector | DNS Servers | Name resolution |
| HTTP | 80 | Collector | CA servers | ADCS ESC8 probe (optional) |
| DNS (AXFR) | 53/TCP | Collector | DNS Servers | Zone transfer probe (optional) |
