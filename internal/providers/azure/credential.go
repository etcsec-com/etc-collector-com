package azure

import (
	"crypto"
	"crypto/x509"
	"fmt"
	"os"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
)

// Credential selection for the Entra app registration.
//
// Two app-only auth methods are supported:
//
//   - client secret     — the historical path, still the default.
//   - client certificate (client_assertion / private_key_jwt) — required by
//     tenants that disable secret creation altogether, which is common in
//     regulated and public-sector environments, and increasingly the direction
//     Microsoft pushes.
//
// The JWT assertion itself is built and signed by azidentity; nothing in this
// file does cryptography beyond parsing the key material.

// HasCertificate reports whether a client certificate is configured, by path
// or as inline PEM.
func (c Config) HasCertificate() bool {
	return c.ClientCertPath != "" || c.ClientCertPEM != ""
}

// HasCredential reports whether any usable app-only credential is configured.
func (c Config) HasCredential() bool {
	return c.ClientSecret != "" || c.HasCertificate()
}

// credential returns the token credential for this client, building it at most
// once. Both the Graph SDK client (Connect) and the raw HTTP path
// (getAccessToken) go through here, so the certificate is parsed once per
// client instead of on every Graph call, and azidentity's own token cache is
// shared between the two.
//
// Guarded by its own mutex: Connect already holds c.mu when it calls this.
func (c *Client) credential() (azcore.TokenCredential, error) {
	c.credMu.Lock()
	defer c.credMu.Unlock()

	if c.cred != nil {
		return c.cred, nil
	}
	cred, err := newCredential(c.config)
	if err != nil {
		return nil, err
	}
	c.cred = cred
	return cred, nil
}

// newCredential builds the app-only credential described by cfg.
//
// A configured certificate wins over a configured secret. The precedence is
// deterministic and documented rather than an error, because the SaaS config
// path can legitimately carry a stale secret alongside a freshly uploaded
// certificate; picking the stronger credential is the safe direction.
func newCredential(cfg Config) (azcore.TokenCredential, error) {
	switch {
	case cfg.HasCertificate():
		certs, key, err := loadCertificate(cfg)
		if err != nil {
			return nil, err
		}
		cred, err := azidentity.NewClientCertificateCredential(cfg.TenantID, cfg.ClientID, certs, key, nil)
		if err != nil {
			return nil, fmt.Errorf("create certificate credential: %w", err)
		}
		return cred, nil

	case cfg.ClientSecret != "":
		cred, err := azidentity.NewClientSecretCredential(cfg.TenantID, cfg.ClientID, cfg.ClientSecret, nil)
		if err != nil {
			return nil, fmt.Errorf("create client secret credential: %w", err)
		}
		return cred, nil

	default:
		return nil, fmt.Errorf("no Entra credential configured: provide either a client secret or a client certificate")
	}
}

// loadCertificate reads and parses the configured certificate. It accepts what
// azidentity.ParseCertificates accepts: an unencrypted PEM bundle (certificate
// + private key), or a PKCS#12 / .pfx bundle with an optional password.
//
// Inline PEM (ClientCertPEM) exists for the SaaS and trial command paths,
// where the credential arrives over the wire and never lands on disk — the
// same path/inline pair the LDAP provider already uses for its CA certificate.
// PKCS#12 is binary, so it is only reachable via ClientCertPath.
func loadCertificate(cfg Config) ([]*x509.Certificate, crypto.PrivateKey, error) {
	var (
		data   []byte
		source string
	)

	switch {
	case cfg.ClientCertPEM != "":
		data = []byte(cfg.ClientCertPEM)
		source = "inline PEM"
	default:
		var err error
		data, err = os.ReadFile(cfg.ClientCertPath)
		if err != nil {
			return nil, nil, fmt.Errorf("read client certificate %s: %w", cfg.ClientCertPath, err)
		}
		source = cfg.ClientCertPath
	}

	if len(data) == 0 {
		return nil, nil, fmt.Errorf("client certificate (%s) is empty", source)
	}

	var password []byte
	if cfg.ClientCertPassword != "" {
		password = []byte(cfg.ClientCertPassword)
	}

	certs, key, err := azidentity.ParseCertificates(data, password)
	if err != nil {
		return nil, nil, fmt.Errorf("parse client certificate (%s): %w%s", source, err, certHint(data, password, err))
	}
	if key == nil {
		return nil, nil, fmt.Errorf("client certificate (%s) contains no private key: the collector needs the private key to sign the client assertion, the app registration holds the public part", source)
	}
	return certs, key, nil
}

// certHint turns the mistakes people actually make into readable advice.
//
// The PKCS#12 case is the one that will generate support tickets: azidentity
// parses .pfx through golang.org/x/crypto/pkcs12, which only understands the
// legacy RC2/3DES + SHA-1 encryption. A .pfx exported by OpenSSL 3 with its
// defaults (AES-256-CBC, SHA-256 MAC) fails with "unknown digest algorithm"
// / "unknown algorithm" — verified locally against OpenSSL 3.6.2. The customer
// has a perfectly valid certificate and no idea why it is rejected.
func certHint(data, password []byte, err error) string {
	text := string(data)
	errText := ""
	if err != nil {
		errText = err.Error()
	}

	switch {
	case strings.Contains(errText, "unknown digest algorithm") ||
		strings.Contains(errText, "unknown algorithm") ||
		strings.Contains(errText, "algorithm"):
		return " (this .pfx uses modern encryption; only the legacy PKCS#12 encryption is supported. Re-export with `openssl pkcs12 -export -legacy ...`, or convert it to a PEM bundle with `openssl pkcs12 -in cert.pfx -out cert.pem -nodes` and point --client-cert at the PEM)"
	case strings.Contains(text, "-----BEGIN CERTIFICATE-----") &&
		!strings.Contains(text, "PRIVATE KEY-----"):
		return " (the file holds a certificate but no private key — it looks like the public .cer uploaded to the Entra app registration; the collector needs the key pair, e.g. the PEM produced with the certificate)"
	case len(password) == 0 && !strings.Contains(text, "-----BEGIN"):
		return " (binary bundle: PKCS#12/.pfx files are usually password-protected — pass --client-cert-password)"
	default:
		return ""
	}
}
