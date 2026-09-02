package azure

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
)

// What these tests do and do NOT prove.
//
// They prove that the right credential TYPE is built from a given config, that
// real key material is parsed (PEM bundle, encrypted PKCS#12, inline PEM), that
// the credential is built once and shared by both call sites, and that broken
// inputs produce actionable errors.
//
// They do NOT prove the token exchange with Entra: signing a client assertion
// and having login.microsoftonline.com accept it requires a tenant with the
// certificate registered on the app, and we have none. That remains unverified
// — see the delivery note.

// testCertPEM returns a self-signed certificate and its private key as a
// single PEM bundle, the shape azidentity.ParseCertificates expects.
func testCertPEM(t *testing.T) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "etc-collector-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	out := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	out = append(out, pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: mustPKCS8(t, key),
	})...)
	return out
}

func mustPKCS8(t *testing.T, key *rsa.PrivateKey) []byte {
	t.Helper()
	b, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	return b
}

func writeTemp(t *testing.T, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return path
}

func TestAzureCredential_UsesCertificateWhenConfigured(t *testing.T) {
	certPEM := testCertPEM(t)
	certPath := writeTemp(t, "client.pem", certPEM)

	cases := []struct {
		name string
		cfg  Config
	}{
		{
			name: "PEM bundle on disk",
			cfg:  Config{TenantID: "t", ClientID: "c", ClientCertPath: certPath},
		},
		{
			name: "inline PEM (SaaS/trial path, never touches disk)",
			cfg:  Config{TenantID: "t", ClientID: "c", ClientCertPEM: string(certPEM)},
		},
		{
			// A stale secret must not shadow a freshly configured certificate:
			// the stronger credential wins, deterministically.
			name: "certificate wins over a secret configured alongside it",
			cfg:  Config{TenantID: "t", ClientID: "c", ClientSecret: "stale-secret", ClientCertPath: certPath},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cred, err := newCredential(tc.cfg)
			if err != nil {
				t.Fatalf("newCredential: %v", err)
			}
			if _, ok := cred.(*azidentity.ClientCertificateCredential); !ok {
				t.Fatalf("expected *azidentity.ClientCertificateCredential, got %T", cred)
			}
		})
	}
}

// exportPFX builds a real password-protected .pfx from the PEM bundle using
// the openssl binary. legacy selects the old RC2/3DES encryption, which is the
// only kind golang.org/x/crypto/pkcs12 (and therefore azidentity) can read.
// Returns "" when openssl is unavailable or the export is unsupported.
func exportPFX(t *testing.T, legacy bool, password string) string {
	t.Helper()
	if _, err := exec.LookPath("openssl"); err != nil {
		return ""
	}
	dir := t.TempDir()
	pemPath := filepath.Join(dir, "pair.pem")
	if err := os.WriteFile(pemPath, testCertPEM(t), 0o600); err != nil {
		t.Fatalf("write pem: %v", err)
	}
	out := filepath.Join(dir, "client.pfx")
	args := []string{"pkcs12", "-export", "-out", out, "-in", pemPath, "-passout", "pass:" + password}
	if legacy {
		args = append(args, "-legacy") // OpenSSL 3+ only
	}
	if err := exec.Command("openssl", args...).Run(); err != nil {
		return "" // OpenSSL 1.x has no -legacy flag; skip rather than guess
	}
	return out
}

// PKCS#12 is what Windows tooling produces and the format the password flag
// exists for. Real .pfx, real password, real parse.
func TestAzureCredential_UsesCertificateFromPKCS12(t *testing.T) {
	pfx := exportPFX(t, true, "hunter2")
	if pfx == "" {
		t.Skip("openssl unavailable or cannot produce a legacy .pfx")
	}

	cred, err := newCredential(Config{
		TenantID:           "t",
		ClientID:           "c",
		ClientCertPath:     pfx,
		ClientCertPassword: "hunter2",
	})
	if err != nil {
		t.Fatalf("newCredential with PKCS#12: %v", err)
	}
	if _, ok := cred.(*azidentity.ClientCertificateCredential); !ok {
		t.Fatalf("expected certificate credential, got %T", cred)
	}
}

// A .pfx exported with OpenSSL 3's defaults (AES-256-CBC, SHA-256 MAC) cannot
// be parsed by the pkcs12 library azidentity uses. The customer's certificate
// is fine, so the error must say what to do rather than leak
// "unknown digest algorithm: 2.16.840.1.101.3.4.2.1".
func TestAzureCredential_ModernPKCS12ErrorIsActionable(t *testing.T) {
	pfx := exportPFX(t, false, "hunter2")
	if pfx == "" {
		t.Skip("openssl unavailable")
	}

	_, err := newCredential(Config{
		TenantID:           "t",
		ClientID:           "c",
		ClientCertPath:     pfx,
		ClientCertPassword: "hunter2",
	})
	if err == nil {
		// OpenSSL 1.x exports legacy by default — then this is simply valid.
		t.Skip("this openssl exports legacy-compatible PKCS#12 by default")
	}
	for _, want := range []string{"-legacy", "PEM"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error should point at the fix (%q), got: %v", want, err)
		}
	}
}

func TestAzureCredential_UsesSecretWhenConfigured(t *testing.T) {
	cred, err := newCredential(Config{TenantID: "t", ClientID: "c", ClientSecret: "s3cr3t"})
	if err != nil {
		t.Fatalf("newCredential: %v", err)
	}
	if _, ok := cred.(*azidentity.ClientSecretCredential); !ok {
		t.Fatalf("expected *azidentity.ClientSecretCredential, got %T", cred)
	}
}

func TestAzureCredential_ErrorsWhenNeitherConfigured(t *testing.T) {
	_, err := newCredential(Config{TenantID: "t", ClientID: "c"})
	if err == nil {
		t.Fatal("expected an error when no credential is configured")
	}
	for _, want := range []string{"client secret", "client certificate"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error should name %q, got: %v", want, err)
		}
	}

	// Same contract at the constructor, which is what the CLI and the SaaS
	// command paths hit first.
	if _, err := NewClient(Config{TenantID: "t", ClientID: "c"}); err == nil {
		t.Fatal("NewClient must reject a config with no credential")
	}
}

// Non-regression: the existing client-secret deployments must keep working
// exactly as before — same constructor contract, same credential type.
func TestAzureCredential_SecretOnlyConfigStillValid(t *testing.T) {
	client, err := NewClient(Config{TenantID: "t", ClientID: "c", ClientSecret: "s"})
	if err != nil {
		t.Fatalf("secret-only config must remain valid: %v", err)
	}
	cred, err := client.credential()
	if err != nil {
		t.Fatalf("credential: %v", err)
	}
	if _, ok := cred.(*azidentity.ClientSecretCredential); !ok {
		t.Fatalf("expected *azidentity.ClientSecretCredential, got %T", cred)
	}
}

// Both credential sites (Connect and getAccessToken) go through Client.credential,
// which must build once: with a certificate, rebuilding per Graph HTTP call would
// re-read and re-parse the key material on every request and defeat azidentity's
// token cache.
func TestAzureCredential_BuiltOnceAndShared(t *testing.T) {
	certPath := writeTemp(t, "client.pem", testCertPEM(t))
	client, err := NewClient(Config{TenantID: "t", ClientID: "c", ClientCertPath: certPath})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	first, err := client.credential()
	if err != nil {
		t.Fatalf("credential: %v", err)
	}
	second, err := client.credential()
	if err != nil {
		t.Fatalf("credential (second call): %v", err)
	}
	if first != second {
		t.Fatal("credential must be built once and reused by both call sites")
	}

	// Deleting the file after the first build must not break later calls —
	// proof the parse happened once.
	if err := os.Remove(certPath); err != nil {
		t.Fatalf("remove cert: %v", err)
	}
	if _, err := client.credential(); err != nil {
		t.Fatalf("cached credential must survive the file going away: %v", err)
	}
}

func TestAzureCredential_CertificateErrorsAreActionable(t *testing.T) {
	// Public part only — the .cer people upload to the app registration.
	block, _ := pem.Decode(testCertPEM(t))
	publicOnly := pem.EncodeToMemory(block)

	cases := []struct {
		name string
		cfg  Config
		want string
	}{
		{
			name: "missing file",
			cfg:  Config{TenantID: "t", ClientID: "c", ClientCertPath: filepath.Join(t.TempDir(), "absent.pem")},
			want: "read client certificate",
		},
		{
			name: "certificate without private key",
			cfg:  Config{TenantID: "t", ClientID: "c", ClientCertPEM: string(publicOnly)},
			want: "private key",
		},
		{
			name: "empty file",
			cfg:  Config{TenantID: "t", ClientID: "c", ClientCertPath: writeTemp(t, "empty.pem", nil)},
			want: "is empty",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := newCredential(tc.cfg)
			if err == nil {
				t.Fatal("expected an error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error should mention %q, got: %v", tc.want, err)
			}
		})
	}
}
