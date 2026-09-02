package saas

import (
	"crypto/tls"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEnsureSelfSignedCert_GeneratesValidPair(t *testing.T) {
	dir := t.TempDir()

	certPath, keyPath, err := ensureSelfSignedCert(dir, "0.0.0.0")
	if err != nil {
		t.Fatalf("ensureSelfSignedCert: %v", err)
	}

	if certPath != filepath.Join(dir, "cert.pem") || keyPath != filepath.Join(dir, "key.pem") {
		t.Fatalf("unexpected paths: cert=%s key=%s", certPath, keyPath)
	}

	// The pair must actually load as a usable TLS keypair — this is what
	// api.Server.Start() does via ListenAndServeTLS.
	pair, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		t.Fatalf("generated pair does not load as a valid TLS keypair: %v", err)
	}

	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		t.Fatalf("parse generated certificate: %v", err)
	}
	if leaf.NotAfter.Before(time.Now().AddDate(1, 0, 0)) {
		t.Fatalf("certificate expires too soon for a bootstrap cert: %s", leaf.NotAfter)
	}
	if leaf.NotBefore.After(time.Now()) {
		t.Fatalf("certificate is not yet valid: %s", leaf.NotBefore)
	}

	foundLocalhost := false
	for _, name := range leaf.DNSNames {
		if name == "localhost" {
			foundLocalhost = true
		}
	}
	if !foundLocalhost {
		t.Fatalf("expected localhost in DNS SANs, got %v", leaf.DNSNames)
	}
}

func TestEnsureSelfSignedCert_NoOpWhenBothFilesExist(t *testing.T) {
	dir := t.TempDir()

	certPath, keyPath, err := ensureSelfSignedCert(dir, "host1")
	if err != nil {
		t.Fatalf("first call: %v", err)
	}
	firstCert, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("read cert: %v", err)
	}

	// Second call, different commonName — must NOT regenerate since both files
	// already exist. An operator-managed or previously-generated pair is not
	// silently replaced on every restart.
	if _, _, err := ensureSelfSignedCert(dir, "a-different-host"); err != nil {
		t.Fatalf("second call: %v", err)
	}
	secondCert, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("read cert after second call: %v", err)
	}
	if string(firstCert) != string(secondCert) {
		t.Fatal("cert.pem was regenerated even though both files already existed")
	}
	_ = keyPath
}

func TestEnsureSelfSignedCert_KeyFileIsPrivate(t *testing.T) {
	dir := t.TempDir()

	_, keyPath, err := ensureSelfSignedCert(dir, "host")
	if err != nil {
		t.Fatalf("ensureSelfSignedCert: %v", err)
	}
	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("stat key file: %v", err)
	}
	if got := info.Mode().Perm(); got != 0600 {
		t.Fatalf("key.pem mode = %o, want 0600", got)
	}
}

func TestEnsureSelfSignedCert_EmptyCommonNameFallsBackToLocalhost(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath, err := ensureSelfSignedCert(dir, "")
	if err != nil {
		t.Fatalf("ensureSelfSignedCert: %v", err)
	}
	pair, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		t.Fatalf("load pair: %v", err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if leaf.Subject.CommonName != "localhost" {
		t.Fatalf("empty commonName should fall back to localhost, got %q", leaf.Subject.CommonName)
	}
}
