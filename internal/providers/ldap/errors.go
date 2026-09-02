package ldap

import (
	"errors"
	"fmt"
	"strings"
)

// ConnectError is the structured error returned by Connect() failures.
//
// Every code maps 1:1 to a section in docs/configuration/ad-troubleshooting.md
// so that downstream consumers (CLI users, SaaS UI, monitoring) can route the
// failure to a known fix without parsing free-form messages.
type ConnectError struct {
	Code       string // Stable, machine-readable identifier (e.g., LDAP_TLS_UNKNOWN_AUTHORITY)
	Message    string // Short human-readable summary
	Resolution string // Actionable fix in one sentence
	DocAnchor  string // Path + anchor to the troubleshooting doc
	Raw        error  // Original underlying error preserved for debugging
}

// Error implements the error interface. Compact form: "[CODE] message: raw".
func (e *ConnectError) Error() string {
	if e.Raw != nil {
		return fmt.Sprintf("[%s] %s: %v", e.Code, e.Message, e.Raw)
	}
	return fmt.Sprintf("[%s] %s", e.Code, e.Message)
}

// Unwrap exposes the underlying error for errors.Is / errors.As traversal.
func (e *ConnectError) Unwrap() error { return e.Raw }

// PrettyPrint produces a multi-line, user-facing description used by the CLI.
//
//	[LDAP_TLS_UNKNOWN_AUTHORITY] LDAP server certificate is not trusted
//	→ Cause: ...
//	→ Fix:   ...
//	→ Docs:  docs/configuration/ad-troubleshooting.md#...
//	→ Raw:   ...
func (e *ConnectError) PrettyPrint() string {
	var b strings.Builder
	fmt.Fprintf(&b, "[%s] %s\n", e.Code, e.Message)
	if e.Resolution != "" {
		fmt.Fprintf(&b, "  → Fix:  %s\n", e.Resolution)
	}
	if e.DocAnchor != "" {
		fmt.Fprintf(&b, "  → Docs: docs/configuration/%s\n", e.DocAnchor)
	}
	if e.Raw != nil {
		fmt.Fprintf(&b, "  → Raw:  %v", e.Raw)
	}
	return b.String()
}

// Codes — keep in sync with docs/configuration/ad-troubleshooting.md.
const (
	CodeUnknown                   = "LDAP_UNKNOWN_ERROR"
	CodeTLSUnknownAuthority       = "LDAP_TLS_UNKNOWN_AUTHORITY"
	CodeTLSIPSANMissing           = "LDAP_TLS_IP_SAN_MISSING"
	CodeTLSHostnameMismatch       = "LDAP_TLS_HOSTNAME_MISMATCH"
	CodeTLSCertExpired            = "LDAP_TLS_CERT_EXPIRED"
	CodeTLSVersionMismatch        = "LDAP_TLS_VERSION_MISMATCH"
	CodeBindInvalidCredentials    = "LDAP_BIND_INVALID_CREDENTIALS"
	CodeBindAccountDisabled       = "LDAP_BIND_ACCOUNT_DISABLED"
	CodeBindPasswordExpired       = "LDAP_BIND_PASSWORD_EXPIRED"
	CodeBindAccountLocked         = "LDAP_BIND_ACCOUNT_LOCKED"
	CodeBindLogonTimeRestricted   = "LDAP_BIND_LOGON_TIME_RESTRICTED"
	CodeBindWorkstationRestricted = "LDAP_BIND_WORKSTATION_RESTRICTED"
	CodeBindMustChangePassword    = "LDAP_BIND_MUST_CHANGE_PASSWORD"
	CodeBindAccountExpired        = "LDAP_BIND_ACCOUNT_EXPIRED"
	CodeChannelBindingRequired    = "LDAP_CHANNEL_BINDING_REQUIRED"
	CodeStrongAuthRequired        = "LDAP_STRONG_AUTH_REQUIRED"
	CodeReferralBadBaseDN         = "LDAP_REFERRAL_BAD_BASE_DN"
	CodeNoSuchObject              = "LDAP_NO_SUCH_OBJECT"
	CodeConnectionRefused         = "LDAP_CONNECTION_REFUSED"
	CodeConnectionTimeout         = "LDAP_CONNECTION_TIMEOUT"
	CodeURLInvalidScheme          = "LDAP_URL_INVALID_SCHEME"
	CodeCACertFileNotFound        = "LDAP_CA_CERT_FILE_NOT_FOUND"
	CodeCACertInvalidPEM          = "LDAP_CA_CERT_INVALID_PEM"
	CodeTLSInvalidMinVersion      = "LDAP_TLS_INVALID_MIN_VERSION"

	// Integrated authentication (T_047/B_036) — kept in sync with
	// docs/configuration/ad-integrated-auth.md, not ad-troubleshooting.md.
	CodeKerberosConfigNotFound    = "LDAP_KRB5_CONFIG_NOT_FOUND"
	CodeKerberosCCacheNotFound    = "LDAP_KRB5_CCACHE_NOT_FOUND"
	CodeKerberosKeytabNotFound    = "LDAP_KRB5_KEYTAB_NOT_FOUND"
	CodeKerberosKeytabBadKey      = "LDAP_KRB5_KEYTAB_BAD_KEY"
	CodeKerberosSPNUnknown        = "LDAP_KRB5_SPN_UNKNOWN"
	CodeKerberosClientUnknown     = "LDAP_KRB5_CLIENT_UNKNOWN"
	CodeKerberosClockSkew         = "LDAP_KRB5_CLOCK_SKEW"
	CodeKerberosTicketExpired     = "LDAP_KRB5_TICKET_EXPIRED"
	CodeKerberosPreauthFailed     = "LDAP_KRB5_PREAUTH_FAILED"
	CodeKerberosRealmUnreachable  = "LDAP_KRB5_REALM_UNREACHABLE"
	CodeKerberosSSPINoCreds       = "LDAP_KRB5_SSPI_NO_CREDENTIALS"
	CodeKerberosSSPILogonDenied   = "LDAP_KRB5_SSPI_LOGON_DENIED"
	CodeKerberosSSPITargetUnknown = "LDAP_KRB5_SSPI_TARGET_UNKNOWN"
)

const docTLS = "ad-troubleshooting.md"
const docKerberos = "ad-integrated-auth.md"

// Classify analyzes a raw error from go-ldap, crypto/tls or net.* and returns
// the matching ConnectError. Falls back to LDAP_UNKNOWN_ERROR.
//
// Match order matters: more specific patterns must come first (e.g., bind
// data codes before the generic "Result Code 49"). The match is case-sensitive
// because the upstream messages are stable across go-ldap versions.
func Classify(raw error) *ConnectError {
	if raw == nil {
		return nil
	}
	// If we're given an already-classified error, propagate as-is.
	var existing *ConnectError
	if errors.As(raw, &existing) {
		return existing
	}

	s := raw.Error()

	// --- Config-time errors raised by buildTLSConfig (must come BEFORE the
	// TLS handshake matchers because the message is our own, not from go-tls). ---
	switch {
	case strings.Contains(s, "read --ldap-ca-cert"):
		return &ConnectError{
			Code:       CodeCACertFileNotFound,
			Message:    "--ldap-ca-cert path is not readable (file missing or permission denied)",
			Resolution: "Verify the file path passed to --ldap-ca-cert exists and is readable by the collector user. Use an absolute path.",
			DocAnchor:  docTLS + "#erreur--ldap_ca_cert_file_not_found",
			Raw:        raw,
		}
	case strings.Contains(s, "ldap-ca-cert content is not a valid PEM"):
		return &ConnectError{
			Code:       CodeCACertInvalidPEM,
			Message:    "--ldap-ca-cert file contents are not a valid PEM certificate",
			Resolution: "Open the file: it must start with '-----BEGIN CERTIFICATE-----'. If you have a DER (.cer/.crt) file, convert with: openssl x509 -inform der -in cert.der -out cert.pem",
			DocAnchor:  docTLS + "#erreur--ldap_ca_cert_invalid_pem",
			Raw:        raw,
		}
	case strings.Contains(s, "invalid --ldap-tls-min-version"):
		return &ConnectError{
			Code:       CodeTLSInvalidMinVersion,
			Message:    "--ldap-tls-min-version value is invalid",
			Resolution: "Use one of: 1.0, 1.1, 1.2, 1.3 (default 1.2). Omit the flag to keep the default.",
			DocAnchor:  docTLS + "#erreur--ldap_tls_invalid_min_version",
			Raw:        raw,
		}
	}

	// --- Integrated authentication (T_047/B_036): setup errors raised by
	// kerberos.go/kerberos_windows.go before any network call is made — our
	// own wrapper messages, must come before the protocol matchers below. ---
	switch {
	case strings.Contains(s, "krb5.conf not readable"):
		return &ConnectError{
			Code:       CodeKerberosConfigNotFound,
			Message:    "krb5.conf not found (required for integrated authentication)",
			Resolution: "Install a krb5.conf at /etc/krb5.conf (see docs/configuration/ad-integrated-auth.md for a minimal example), or set Config.Krb5Config to an explicit path.",
			DocAnchor:  docKerberos + "#krb5conf-introuvable",
			Raw:        raw,
		}
	case strings.Contains(s, "no Kerberos ticket cache"):
		return &ConnectError{
			Code:       CodeKerberosCCacheNotFound,
			Message:    "No Kerberos ticket found for integrated authentication",
			Resolution: "Run kinit for the collector's service account, verify KRB5CCNAME if set, or configure kerberosKeytab to use a keytab instead of the ambient ticket cache.",
			DocAnchor:  docKerberos + "#pas-de-ticket-kerberos-trouve",
			Raw:        raw,
		}
	case strings.Contains(s, "keytab file not found"):
		return &ConnectError{
			Code:       CodeKerberosKeytabNotFound,
			Message:    "kerberosKeytab path is not readable",
			Resolution: "Verify the keytab file exists at the configured path and is readable by the collector's service account.",
			DocAnchor:  docKerberos + "#keytab-introuvable",
			Raw:        raw,
		}
	case strings.Contains(s, "kerberosPrincipal") && strings.Contains(s, "required"):
		return &ConnectError{
			Code:       CodeKerberosKeytabNotFound,
			Message:    "kerberosKeytab is set but kerberosPrincipal is missing",
			Resolution: `Set kerberosPrincipal to the account matching the keytab, in "user@REALM" form (realm in upper case).`,
			DocAnchor:  docKerberos + "#keytab-introuvable",
			Raw:        raw,
		}
	}

	// --- Integrated authentication (T_047/B_036): Kerberos protocol errors,
	// surfaced by gokrb5 during the GSSAPI handshake (Linux/macOS) or
	// documented SSPI/secur32 error text (Windows — not empirically verified
	// on this ticket, no Windows host was available to trigger a live
	// failure; matched against Microsoft's published error strings). ---
	switch {
	// gokrb5's keytab lookup: wrong principal, wrong kvno, or the keytab was
	// regenerated after the AD password last changed.
	case strings.Contains(s, "matching key not found in keytab"):
		return &ConnectError{
			Code:       CodeKerberosKeytabBadKey,
			Message:    "Keytab does not contain a usable key for this account",
			Resolution: "Regenerate the keytab (ktpass/ktutil) for the exact account and current key version — this happens after the AD password was reset without refreshing the keytab.",
			DocAnchor:  docKerberos + "#cle-introuvable-dans-le-keytab",
			Raw:        raw,
		}
	// KDC_ERR_S_PRINCIPAL_UNKNOWN — the LDAP SPN (ldap/<host>) isn't
	// registered on any account the KDC knows about.
	case strings.Contains(s, "KDC_ERR_S_PRINCIPAL_UNKNOWN"):
		return &ConnectError{
			Code:       CodeKerberosSPNUnknown,
			Message:    "Service Principal Name not found in Active Directory",
			Resolution: `Register the SPN on the DC's own computer account (it usually already has ldap/<hostname> and ldap/<hostname>.<domain> by default — verify with setspn -L <DC-computer-account>), or set servicePrincipalName explicitly if the DC's LDAP endpoint uses a different name.`,
			DocAnchor:  docKerberos + "#spn-introuvable",
			Raw:        raw,
		}
	// KDC_ERR_C_PRINCIPAL_UNKNOWN — our own principal (the keytab account, or
	// whatever kinit'd) isn't a valid AD account, or was deleted.
	case strings.Contains(s, "KDC_ERR_C_PRINCIPAL_UNKNOWN"):
		return &ConnectError{
			Code:       CodeKerberosClientUnknown,
			Message:    "The Kerberos client principal is not a valid AD account",
			Resolution: "Verify kerberosPrincipal (or the account used for kinit/the service identity) still exists in AD and is spelled exactly right, including the realm.",
			DocAnchor:  docKerberos + "#compte-kerberos-introuvable",
			Raw:        raw,
		}
	case strings.Contains(s, "KRB_AP_ERR_SKEW"):
		return &ConnectError{
			Code:       CodeKerberosClockSkew,
			Message:    "Clock skew too great between the collector host and the domain controller",
			Resolution: "Synchronize the collector host's clock via NTP against the same time source as the domain (Kerberos rejects anything past ~5 minutes of drift by default).",
			DocAnchor:  docKerberos + "#horloge-desynchronisee",
			Raw:        raw,
		}
	case strings.Contains(s, "KRB_AP_ERR_TKT_EXPIRED"):
		return &ConnectError{
			Code:       CodeKerberosTicketExpired,
			Message:    "Kerberos ticket has expired",
			Resolution: "Run kinit again to refresh the ambient ticket cache, or switch to kerberosKeytab so the collector renews tickets itself without an interactive session.",
			DocAnchor:  docKerberos + "#ticket-expire",
			Raw:        raw,
		}
	case strings.Contains(s, "KDC_ERR_PREAUTH_FAILED"):
		return &ConnectError{
			Code:       CodeKerberosPreauthFailed,
			Message:    "Kerberos pre-authentication failed",
			Resolution: "The keytab's key (or the ticket cache's password-derived key) doesn't match what AD has on record — regenerate the keytab, or re-run kinit with the current password.",
			DocAnchor:  docKerberos + "#pre-authentification-echouee",
			Raw:        raw,
		}
	// gokrb5 cannot find the realm in krb5.conf (missing [realms] entry) and
	// falls back to DNS SRV discovery, which also fails — this is the "wrong
	// or unconfigured realm" case.
	case strings.Contains(s, "no KDC SRV records found for realm"):
		return &ConnectError{
			Code:       CodeKerberosRealmUnreachable,
			Message:    "Kerberos realm not found (no KDC reachable for this realm)",
			Resolution: `Verify the realm name (it's the AD domain in UPPER CASE, e.g. "EXAMPLE.COM") and that krb5.conf's [realms] section — or DNS SRV records _kerberos._tcp.<realm> — point at a reachable domain controller.`,
			DocAnchor:  docKerberos + "#realm-introuvable",
			Raw:        raw,
		}
	// --- Windows SSPI (secur32.dll) — documented Microsoft error text,
	// see the comment on this switch block. ---
	case strings.Contains(s, "specified target is unknown or unreachable"):
		return &ConnectError{
			Code:       CodeKerberosSSPITargetUnknown,
			Message:    "SSPI: target SPN is unknown or unreachable (SEC_E_TARGET_UNKNOWN)",
			Resolution: "Same root cause as LDAP_KRB5_SPN_UNKNOWN: verify the DC's ldap/<hostname> SPN is registered, or set servicePrincipalName explicitly.",
			DocAnchor:  docKerberos + "#spn-introuvable",
			Raw:        raw,
		}
	case strings.Contains(s, "No credentials are available"):
		return &ConnectError{
			Code:       CodeKerberosSSPINoCreds,
			Message:    "SSPI: no credentials available for the current process identity (SEC_E_NO_CREDENTIALS)",
			Resolution: "The account the collector service runs as has no usable Kerberos identity — verify it's a domain account (ideally a gMSA) and the host is domain-joined, not a local/LocalService account on a workgroup machine.",
			DocAnchor:  docKerberos + "#pas-didentite-windows-utilisable",
			Raw:        raw,
		}
	case strings.Contains(s, "logon attempt failed"):
		return &ConnectError{
			Code:       CodeKerberosSSPILogonDenied,
			Message:    "SSPI: logon denied for the current process identity (SEC_E_LOGON_DENIED)",
			Resolution: "Verify the service account is enabled, not locked out, and has not had its password/gMSA managed-password state broken (re-run Reset-ADServiceAccountPassword for a gMSA in doubt).",
			DocAnchor:  docKerberos + "#identite-windows-refusee",
			Raw:        raw,
		}
	}

	// --- TLS errors (handshake / verification) ---
	switch {
	case strings.Contains(s, "x509: cannot validate certificate") && strings.Contains(s, "doesn't contain any IP SANs"):
		return &ConnectError{
			Code:       CodeTLSIPSANMissing,
			Message:    "LDAP URL uses an IP address but the certificate has no IP SAN",
			Resolution: "Use the DC FQDN listed in the certificate SAN (run: openssl s_client -connect HOST:636 -showcerts).",
			DocAnchor:  docTLS + "#erreur--x509-cannot-validate-certificate-for-xxx-because-it-doesnt-contain-any-ip-sans",
			Raw:        raw,
		}
	case strings.Contains(s, "x509: certificate is valid for"):
		return &ConnectError{
			Code:       CodeTLSHostnameMismatch,
			Message:    "LDAP URL hostname doesn't match any certificate SAN",
			Resolution: "Use a hostname listed in the certificate SAN, or update DNS to align names.",
			DocAnchor:  docTLS + "#erreur--x509-certificate-is-valid-for-x-not-y",
			Raw:        raw,
		}
	case strings.Contains(s, "x509: certificate has expired") || strings.Contains(s, "x509: certificate is not yet valid") || strings.Contains(s, "certificate has expired or is not yet valid"):
		return &ConnectError{
			Code:       CodeTLSCertExpired,
			Message:    "LDAP server certificate is expired or not yet valid",
			Resolution: "Renew the DC certificate, or check the collector host clock (NTP).",
			DocAnchor:  docTLS + "#erreur--x509-certificate-has-expired-or-is-not-yet-valid",
			Raw:        raw,
		}
	case strings.Contains(s, "x509: certificate signed by unknown authority") || strings.Contains(s, "certificate is not trusted"):
		return &ConnectError{
			Code:       CodeTLSUnknownAuthority,
			Message:    "LDAP server certificate is not trusted by the client",
			Resolution: "Install the DC's root CA in the system trust store, or pass --ldap-ca-cert /path/to/ca.pem.",
			DocAnchor:  docTLS + "#erreur--x509-certificate-signed-by-unknown-authority",
			Raw:        raw,
		}
	case strings.Contains(s, "tls: protocol version not supported") || strings.Contains(s, "tls: no supported versions"):
		return &ConnectError{
			Code:       CodeTLSVersionMismatch,
			Message:    "Required TLS version is not supported by the LDAP server",
			Resolution: "Lower --ldap-tls-min-version (e.g. 1.2) or upgrade the DC to support the required version.",
			DocAnchor:  docTLS + "#erreur--tls-protocol-version-not-supported",
			Raw:        raw,
		}
	}

	// --- LDAP bind data codes (data XXX inside Result Code 49 message) ---
	// Match against the AcceptSecurityContext "data NNN" suffix used by AD.
	if strings.Contains(s, "Result Code 49") || strings.Contains(s, "Invalid Credentials") {
		switch {
		// Channel binding sentinel (SEC_E_BAD_BINDINGS) — match this *before*
		// the generic "data 52e" because some go-ldap messages omit "data " prefix.
		case strings.Contains(s, "80090346"):
			return bindErr(CodeChannelBindingRequired, "DC enforces TLS channel binding",
				"Channel binding is not yet implemented in the collector. Ask the AD team to lower LdapEnforceChannelBinding to 1 if possible.",
				docTLS+"#channel-binding-requis-ldapenforcechannelbinding2", raw)
		case strings.Contains(s, "data 533"):
			return bindErr(CodeBindAccountDisabled, "Bind failed: account is disabled",
				"Re-enable the AD service account.",
				docTLS+"#erreur--ldap-result-code-49-invalid-credentials", raw)
		case strings.Contains(s, "data 532"):
			return bindErr(CodeBindPasswordExpired, "Bind failed: password expired",
				"Reset the service account password and update the collector config.",
				docTLS+"#erreur--ldap-result-code-49-invalid-credentials", raw)
		case strings.Contains(s, "data 775"):
			return bindErr(CodeBindAccountLocked, "Bind failed: account is locked",
				"Unlock the AD service account and review brute-force triggers.",
				docTLS+"#erreur--ldap-result-code-49-invalid-credentials", raw)
		case strings.Contains(s, "data 530"):
			return bindErr(CodeBindLogonTimeRestricted, "Bind failed: logon time restriction",
				"Adjust the account's logon hours, or pick a different service account without time limits.",
				docTLS+"#erreur--ldap-result-code-49-invalid-credentials", raw)
		case strings.Contains(s, "data 531"):
			return bindErr(CodeBindWorkstationRestricted, "Bind failed: workstation restriction",
				"Add the collector host to the account's allowed workstations, or remove the restriction.",
				docTLS+"#erreur--ldap-result-code-49-invalid-credentials", raw)
		case strings.Contains(s, "data 773"):
			return bindErr(CodeBindMustChangePassword, "Bind failed: must change password at next logon",
				"Reset the password (with 'change at next logon' cleared) and update the config.",
				docTLS+"#erreur--ldap-result-code-49-invalid-credentials", raw)
		case strings.Contains(s, "data 701"):
			return bindErr(CodeBindAccountExpired, "Bind failed: account is expired",
				"Extend the AD account expiration date.",
				docTLS+"#erreur--ldap-result-code-49-invalid-credentials", raw)
		default:
			return bindErr(CodeBindInvalidCredentials, "Bind failed: invalid bindDN or password (AD code 52e)",
				"Verify the bindDN spelling and the password. Test with ldapsearch as a cross-check.",
				docTLS+"#erreur--ldap-result-code-49-invalid-credentials", raw)
		}
	}

	// --- LDAP protocol errors ---
	switch {
	case strings.Contains(s, "Result Code 8") || strings.Contains(s, "Strong Auth Required"):
		return &ConnectError{
			Code:       CodeStrongAuthRequired,
			Message:    "DC refuses unsigned binds (LDAP signing enforced)",
			Resolution: "Switch to LDAPS (--ldap-url ldaps://...:636) or enable StartTLS (--ldap-start-tls).",
			DocAnchor:  docTLS + "#erreur--ldap-result-code-8-strong-auth-required",
			Raw:        raw,
		}
	case strings.Contains(s, "Result Code 10") || strings.Contains(s, "Referral"):
		return &ConnectError{
			Code:       CodeReferralBadBaseDN,
			Message:    "Base DN is not served by this DC (referral returned)",
			Resolution: "Use the defaultNamingContext of the target DC (query 'rootDSE' if unsure).",
			DocAnchor:  docTLS + "#erreur--ldap-result-code-10-referral",
			Raw:        raw,
		}
	case strings.Contains(s, "Result Code 32") || strings.Contains(s, "No Such Object"):
		return &ConnectError{
			Code:       CodeNoSuchObject,
			Message:    "Object not found at the given DN",
			Resolution: "Verify the base DN exists. For audit, use the domain root (DC=example,DC=com).",
			DocAnchor:  docTLS + "#erreur--ldap-result-code-32-no-such-object",
			Raw:        raw,
		}
	}

	// --- Network errors ---
	switch {
	case strings.Contains(s, "connection refused") || strings.Contains(s, "actively refused"):
		return &ConnectError{
			Code:       CodeConnectionRefused,
			Message:    "DC port is not accessible (connection refused)",
			Resolution: "Verify the port (636 LDAPS, 389 LDAP) and that Schannel binds a cert. See ad-tls-certificates.md#7-cas-particulier--dc-sans-certificat-ldaps.",
			DocAnchor:  docTLS + "#erreur--dial-tcp-xxx636-connection-refused",
			Raw:        raw,
		}
	case strings.Contains(s, "i/o timeout") || strings.Contains(s, "did not properly respond") || strings.Contains(s, "no route to host"):
		return &ConnectError{
			Code:       CodeConnectionTimeout,
			Message:    "DC is unreachable (timeout)",
			Resolution: "Check firewall rules, DNS resolution, and that the DC is up. Try: nc -zv DC 636.",
			DocAnchor:  docTLS + "#erreur--dial-tcp-xxx636-io-timeout",
			Raw:        raw,
		}
	case strings.Contains(s, "Unknown scheme"):
		return &ConnectError{
			Code:       CodeURLInvalidScheme,
			Message:    "LDAP URL must start with ldap:// or ldaps://",
			Resolution: "Prefix the URL: --ldap-url ldaps://dc.example.com:636",
			DocAnchor:  docTLS + "#erreur--unknown-scheme-x",
			Raw:        raw,
		}
	}

	return &ConnectError{
		Code:       CodeUnknown,
		Message:    "Unclassified LDAP error",
		Resolution: "See the raw error for details. If this is a recurring case, please file an issue.",
		DocAnchor:  docTLS,
		Raw:        raw,
	}
}

func bindErr(code, msg, fix, anchor string, raw error) *ConnectError {
	return &ConnectError{Code: code, Message: msg, Resolution: fix, DocAnchor: anchor, Raw: raw}
}
