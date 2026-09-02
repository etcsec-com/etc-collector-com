package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestResolveEnrollToken_Precedence — B_030/T_045: explicit flag > file/stdin > env >
// viper (config file). Also proves --enroll-token keeps working unmodified.
func TestResolveEnrollToken_Precedence(t *testing.T) {
	t.Run("explicit flag wins over everything else", func(t *testing.T) {
		dir := t.TempDir()
		tokenFile := filepath.Join(dir, "token")
		if err := os.WriteFile(tokenFile, []byte("from-file"), 0600); err != nil {
			t.Fatalf("write token file: %v", err)
		}
		t.Setenv("ETCSEC_ENROLL_TOKEN", "from-env")

		got, err := resolveEnrollToken("from-flag", tokenFile, false, strings.NewReader("from-stdin\n"), "from-viper")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != "from-flag" {
			t.Fatalf("got %q, want the explicit flag value", got)
		}
	})

	t.Run("file wins over env and viper", func(t *testing.T) {
		dir := t.TempDir()
		tokenFile := filepath.Join(dir, "token")
		if err := os.WriteFile(tokenFile, []byte("from-file\n"), 0600); err != nil {
			t.Fatalf("write token file: %v", err)
		}
		t.Setenv("ETCSEC_ENROLL_TOKEN", "from-env")

		got, err := resolveEnrollToken("", tokenFile, false, nil, "from-viper")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != "from-file" {
			t.Fatalf("got %q, want the file contents (trimmed)", got)
		}
	})

	t.Run("stdin wins over env and viper", func(t *testing.T) {
		t.Setenv("ETCSEC_ENROLL_TOKEN", "from-env")

		got, err := resolveEnrollToken("", "", true, strings.NewReader("from-stdin\n"), "from-viper")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != "from-stdin" {
			t.Fatalf("got %q, want the stdin line (trimmed)", got)
		}
	})

	t.Run("env wins over viper", func(t *testing.T) {
		t.Setenv("ETCSEC_ENROLL_TOKEN", "from-env")

		got, err := resolveEnrollToken("", "", false, nil, "from-viper")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != "from-env" {
			t.Fatalf("got %q, want the env value", got)
		}
	})

	t.Run("viper is the last resort", func(t *testing.T) {
		got, err := resolveEnrollToken("", "", false, nil, "from-viper")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != "from-viper" {
			t.Fatalf("got %q, want the viper value", got)
		}
	})

	t.Run("nothing provided anywhere returns empty, no error", func(t *testing.T) {
		got, err := resolveEnrollToken("", "", false, nil, "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != "" {
			t.Fatalf("got %q, want empty", got)
		}
	})
}

func TestResolveEnrollToken_FileAndStdinMutuallyExclusive(t *testing.T) {
	dir := t.TempDir()
	tokenFile := filepath.Join(dir, "token")
	if err := os.WriteFile(tokenFile, []byte("x"), 0600); err != nil {
		t.Fatalf("write token file: %v", err)
	}

	_, err := resolveEnrollToken("", tokenFile, true, strings.NewReader("y\n"), "")
	if err == nil {
		t.Fatal("expected an error when both --enroll-token-file and --enroll-token-stdin are set")
	}
}

func TestResolveEnrollToken_EmptyFileIsAnError(t *testing.T) {
	dir := t.TempDir()
	tokenFile := filepath.Join(dir, "token")
	if err := os.WriteFile(tokenFile, []byte("   \n"), 0600); err != nil {
		t.Fatalf("write token file: %v", err)
	}

	if _, err := resolveEnrollToken("", tokenFile, false, nil, ""); err == nil {
		t.Fatal("expected an error for a whitespace-only token file — silently falling through to unenrolled would hide the mistake")
	}
}

func TestResolveEnrollToken_MissingFileIsAnError(t *testing.T) {
	if _, err := resolveEnrollToken("", filepath.Join(t.TempDir(), "absent"), false, nil, ""); err == nil {
		t.Fatal("expected an error for a nonexistent --enroll-token-file")
	}
}

func TestResolveEnrollToken_EmptyStdinIsAnError(t *testing.T) {
	if _, err := resolveEnrollToken("", "", true, strings.NewReader(""), ""); err == nil {
		t.Fatal("expected an error when --enroll-token-stdin is set but stdin has no line to read")
	}
}

func TestResolveEnrollToken_StdinIsExplicitNotAutodetected(t *testing.T) {
	// Sanity: without --enroll-token-stdin, a readable stdin is simply never consulted.
	t.Setenv("ETCSEC_ENROLL_TOKEN", "")
	got, err := resolveEnrollToken("", "", false, strings.NewReader("should-not-be-read\n"), "from-viper")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "from-viper" {
		t.Fatalf("got %q — stdin must not be read unless --enroll-token-stdin is set", got)
	}
}
