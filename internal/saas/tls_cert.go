package saas

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// ensureSelfSignedCert makes sure a TLS certificate+key pair exists under certDir
// (cert.pem + key.pem). If both files are present, no-op. If either is missing, a
// fresh self-signed pair is generated and written.
//
// B_136 (T_060): the model here is exactly ensureJWTKeys (jwt_keys.go) — generate a
// bootstrap credential on demand so a fresh or upgraded install works with zero
// operator action, rather than refusing to start or shipping a real gap (HTTP on a
// network-reachable interface) until someone manually provisions a certificate.
//
// This is a bootstrap certificate, not a managed one: no rotation, no revocation, no
// ACME/Let's Encrypt integration — the collector talks to its own admin GUI over an
// unverified connection either way (a self-signed cert can't be validated against a
// public CA), so a 10-year validity avoids building expiry handling for a credential
// that provides confidentiality against passive network sniffing, not identity
// assurance. An operator who wants a real, browser-trusted certificate provides
// server.tlsCertFile/tlsKeyFile in config.yaml, which always takes precedence — see
// resolveGUITLS.
func ensureSelfSignedCert(certDir, commonName string) (certPath, keyPath string, err error) {
	certPath = filepath.Join(certDir, "cert.pem")
	keyPath = filepath.Join(certDir, "key.pem")

	_, errCert := os.Stat(certPath)
	_, errKey := os.Stat(keyPath)
	if errCert == nil && errKey == nil {
		return certPath, keyPath, nil
	}

	if err := os.MkdirAll(certDir, 0o700); err != nil {
		return "", "", fmt.Errorf("create %s: %w", certDir, err)
	}

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", fmt.Errorf("generate RSA key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return "", "", fmt.Errorf("generate serial number: %w", err)
	}

	if commonName == "" {
		commonName = "localhost"
	}

	template := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"ETC Collector (self-signed, bootstrap)"},
		},
		NotBefore:             time.Now().Add(-time.Hour), // clock skew tolerance
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              dnsNamesFor(commonName),
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return "", "", fmt.Errorf("create certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		return "", "", fmt.Errorf("write %s: %w", certPath, err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return "", "", fmt.Errorf("write %s: %w", keyPath, err)
	}
	return certPath, keyPath, nil
}

// dnsNamesFor returns the SAN DNS names for a bootstrap certificate: the bind host
// itself (when it's a real hostname rather than an IP or wildcard address) plus
// "localhost", so a browser or curl reaching the collector via either name at least
// gets a name-matching (still untrusted-CA) certificate.
func dnsNamesFor(commonName string) []string {
	names := []string{"localhost"}
	if commonName != "" && commonName != "localhost" && net.ParseIP(commonName) == nil && commonName != "0.0.0.0" {
		names = append(names, commonName)
	}
	return names
}
