package ldap

import (
	"errors"
	"testing"
)

func TestClassify(t *testing.T) {
	cases := []struct {
		name     string
		input    string
		wantCode string
	}{
		// TLS
		{"unknown CA Linux", "ldap: connect: LDAP Result Code 200 \"Network Error\": tls: failed to verify certificate: x509: certificate signed by unknown authority", CodeTLSUnknownAuthority},
		{"unknown CA macOS", "tls: failed to verify certificate: x509: \"DC-01.example.com\" certificate is not trusted", CodeTLSUnknownAuthority},
		{"IP SAN missing", "x509: cannot validate certificate for 192.0.2.83 because it doesn't contain any IP SANs", CodeTLSIPSANMissing},
		{"hostname mismatch", "x509: certificate is valid for DC-01.example.com, not localhost", CodeTLSHostnameMismatch},
		{"cert expired", "x509: certificate has expired or is not yet valid", CodeTLSCertExpired},
		{"tls version", "tls: protocol version not supported", CodeTLSVersionMismatch},

		// Bind data codes — order-sensitive (data 80090346 must hit channel binding before generic 49)
		{"channel binding", "LDAP Result Code 49 \"Invalid Credentials\": 80090346: LdapErr: ...", CodeChannelBindingRequired},
		{"account disabled", "LDAP Result Code 49 \"Invalid Credentials\": 80090308: LdapErr: data 533, v4f7c", CodeBindAccountDisabled},
		{"password expired", "LDAP Result Code 49 \"Invalid Credentials\": 80090308: LdapErr: data 532, v4f7c", CodeBindPasswordExpired},
		{"account locked", "LDAP Result Code 49 \"Invalid Credentials\": 80090308: LdapErr: data 775, v4f7c", CodeBindAccountLocked},
		{"logon time", "LDAP Result Code 49 \"Invalid Credentials\": 80090308: LdapErr: data 530, v4f7c", CodeBindLogonTimeRestricted},
		{"workstation", "LDAP Result Code 49 \"Invalid Credentials\": 80090308: LdapErr: data 531, v4f7c", CodeBindWorkstationRestricted},
		{"must change pw", "LDAP Result Code 49 \"Invalid Credentials\": 80090308: LdapErr: data 773, v4f7c", CodeBindMustChangePassword},
		{"account expired", "LDAP Result Code 49 \"Invalid Credentials\": 80090308: LdapErr: data 701, v4f7c", CodeBindAccountExpired},
		{"bad credentials default", "LDAP Result Code 49 \"Invalid Credentials\": 80090308: LdapErr: DSID-0C090434, comment: AcceptSecurityContext error, data 52e, v4f7c", CodeBindInvalidCredentials},

		// LDAP protocol
		{"strong auth required", "LDAP Result Code 8 \"Strong Auth Required\": ...", CodeStrongAuthRequired},
		{"referral", "LDAP Result Code 10 \"Referral\": 0000202B: RefErr: DSID-03100838, data 0, 1 access points\n\tref 1: 'wrong.cc'", CodeReferralBadBaseDN},
		{"no such object", "LDAP Result Code 32 \"No Such Object\": ...", CodeNoSuchObject},

		// Network
		{"connection refused linux", "ldap: connect: LDAP Result Code 200 \"Network Error\": dial tcp 10.0.0.10:6360: connect: connection refused", CodeConnectionRefused},
		{"connection refused windows", "dial tcp [::1]:6360: connectex: No connection could be made because the target machine actively refused it.", CodeConnectionRefused},
		{"timeout linux", "dial tcp 10.0.0.99:636: i/o timeout", CodeConnectionTimeout},
		{"timeout windows", "dial tcp 10.0.0.99:636: connectex: A connection attempt failed because the connected party did not properly respond after a period of time", CodeConnectionTimeout},
		{"unknown scheme", "ldap: connect: LDAP Result Code 200 \"Network Error\": Unknown scheme 'dc-01.example.com'", CodeURLInvalidScheme},

		// Config-time errors (raised by buildTLSConfig in v3.1.12)
		{"ca-cert file not found", "read --ldap-ca-cert \"/nope.pem\": open /nope.pem: no such file or directory", CodeCACertFileNotFound},
		{"ca-cert windows path missing", "read --ldap-ca-cert \"C:\\nope.pem\": open C:\\nope.pem: The system cannot find the file specified.", CodeCACertFileNotFound},
		{"ca-cert invalid PEM", "--ldap-ca-cert content is not a valid PEM certificate (5 bytes loaded)", CodeCACertInvalidPEM},
		{"tls min version invalid", "invalid --ldap-tls-min-version \"xxx\" (expected 1.0, 1.1, 1.2 or 1.3)", CodeTLSInvalidMinVersion},

		// Integrated authentication (T_047/B_036) — setup errors, our own wrapper text
		{"krb5.conf missing", "krb5.conf not readable at \"/etc/krb5.conf\": stat /etc/krb5.conf: no such file or directory (set Config.Krb5Config, or install one at /etc/krb5.conf)", CodeKerberosConfigNotFound},
		{"ccache missing", "no Kerberos ticket cache at \"/tmp/krb5cc_501\": stat /tmp/krb5cc_501: no such file or directory", CodeKerberosCCacheNotFound},
		{"keytab file missing", "keytab file not found at \"/etc/etc-collector/collector.keytab\": stat /etc/etc-collector/collector.keytab: no such file or directory", CodeKerberosKeytabNotFound},
		{"keytab without principal", "kerberosPrincipal is required when kerberosKeytab is set (format: user@REALM)", CodeKerberosKeytabNotFound},

		// Integrated authentication — Kerberos protocol errors (gokrb5, Linux/macOS)
		{"keytab bad key", "matching key not found in keytab. Looking for \"svc-etccollector\" realm: EXAMPLE.COM kvno: 3 etype: 18", CodeKerberosKeytabBadKey},
		{"spn unknown", "KRB Error: KDC_ERR_S_PRINCIPAL_UNKNOWN Server not found in Kerberos database", CodeKerberosSPNUnknown},
		{"client unknown", "KRB Error: KDC_ERR_C_PRINCIPAL_UNKNOWN Client not found in Kerberos database", CodeKerberosClientUnknown},
		{"clock skew", "KRB Error: KRB_AP_ERR_SKEW Clock skew too great", CodeKerberosClockSkew},
		{"ticket expired", "KRB Error: KRB_AP_ERR_TKT_EXPIRED Ticket expired", CodeKerberosTicketExpired},
		{"preauth failed", "KRB Error: KDC_ERR_PREAUTH_FAILED Pre-authentication information was invalid", CodeKerberosPreauthFailed},
		{"realm unreachable", "no KDC SRV records found for realm WRONG.REALM", CodeKerberosRealmUnreachable},

		// Integrated authentication — Windows SSPI (documented Microsoft error text)
		{"sspi target unknown", "AcquireCredentialsHandle: The specified target is unknown or unreachable.", CodeKerberosSSPITargetUnknown},
		{"sspi no credentials", "No credentials are available in the security package", CodeKerberosSSPINoCreds},
		{"sspi logon denied", "The logon attempt failed", CodeKerberosSSPILogonDenied},

		// Fallback
		{"unclassified", "weird error nobody knows", CodeUnknown},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Classify(errors.New(tc.input))
			if got == nil {
				t.Fatalf("Classify returned nil")
			}
			if got.Code != tc.wantCode {
				t.Fatalf("got code %q, want %q (input: %q)", got.Code, tc.wantCode, tc.input)
			}
			if got.Raw == nil {
				t.Errorf("Raw should be preserved")
			}
			if got.Resolution == "" {
				t.Errorf("Resolution should be set")
			}
			if got.DocAnchor == "" {
				t.Errorf("DocAnchor should be set")
			}
		})
	}
}

func TestClassifyNil(t *testing.T) {
	if got := Classify(nil); got != nil {
		t.Fatalf("Classify(nil) should return nil, got %v", got)
	}
}

func TestClassifyAlreadyClassified(t *testing.T) {
	original := &ConnectError{Code: CodeTLSCertExpired, Message: "x", Raw: errors.New("y")}
	got := Classify(original)
	if got != original {
		t.Fatalf("Classify of already-classified should return identity")
	}
}

func TestConnectErrorPrettyPrint(t *testing.T) {
	ce := &ConnectError{
		Code:       CodeTLSUnknownAuthority,
		Message:    "LDAP server certificate is not trusted by the client",
		Resolution: "Install the DC's root CA.",
		DocAnchor:  "ad-troubleshooting.md#erreur--x509-certificate-signed-by-unknown-authority",
		Raw:        errors.New("x509: certificate signed by unknown authority"),
	}
	out := ce.PrettyPrint()
	for _, want := range []string{"[LDAP_TLS_UNKNOWN_AUTHORITY]", "Fix:", "Docs:", "Raw:", "Install the DC's root CA"} {
		if !contains(out, want) {
			t.Errorf("PrettyPrint missing %q\nGot:\n%s", want, out)
		}
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
