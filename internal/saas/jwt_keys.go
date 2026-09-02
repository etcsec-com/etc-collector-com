package saas

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
)

// EnsureJWTKeys makes sure an RSA-2048 keypair exists under keysDir
// (private.pem + public.pem). If both files are present and valid, no-op.
// If either is missing, a fresh keypair is generated and written.
//
// Used by StartEmbeddedGUI so daemon-mode installs don't need a manual
// `openssl genrsa` step — fresh installs get a working /api/v1/auth/token
// endpoint out of the box. Files are written with 0600 (private) /
// 0644 (public); directory created with 0700.
//
// Exported (B_084, T_067): the standalone `server` command (cmd/etc-collector)
// and its Windows service variant never called this at all — only
// cfg.LoadKeys(), which reads existing files but generates nothing — so a fresh
// standalone install had no private key, and every POST /api/v1/auth/token
// failed with 500 token_generation_failed. Same generator, all three startup
// paths now.
func EnsureJWTKeys(keysDir string) error {
	privPath := filepath.Join(keysDir, "private.pem")
	pubPath := filepath.Join(keysDir, "public.pem")

	_, errPriv := os.Stat(privPath)
	_, errPub := os.Stat(pubPath)
	if errPriv == nil && errPub == nil {
		return nil // both present
	}

	if err := os.MkdirAll(keysDir, 0o700); err != nil {
		return fmt.Errorf("create %s: %w", keysDir, err)
	}

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("generate RSA key: %w", err)
	}

	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(priv),
	})
	pubBytes, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return fmt.Errorf("marshal public key: %w", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubBytes,
	})

	if err := os.WriteFile(privPath, privPEM, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", privPath, err)
	}
	if err := os.WriteFile(pubPath, pubPEM, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", pubPath, err)
	}
	return nil
}
