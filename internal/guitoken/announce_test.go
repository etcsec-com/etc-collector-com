package guitoken

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestAnnounceFirstRun_WritesFirstRunFileOnly — B_135 (T_060). Proves the token lands
// in the dedicated .firstrun file (0600) and nowhere else in the directory — the whole
// point being that this file, unlike collector.log, is never returned by GET_LOGS.
func TestAnnounceFirstRun_WritesFirstRunFileOnly(t *testing.T) {
	dir := t.TempDir()
	token, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	if err := AnnounceFirstRun(dir, token); err != nil {
		t.Fatalf("AnnounceFirstRun: %v", err)
	}

	path := filepath.Join(dir, "gui-token.firstrun")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read gui-token.firstrun: %v", err)
	}
	if !strings.Contains(string(data), token) {
		t.Fatalf("gui-token.firstrun does not contain the token: %s", data)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat gui-token.firstrun: %v", err)
	}
	if got := info.Mode().Perm(); got != 0600 {
		t.Fatalf("gui-token.firstrun mode = %o, want 0600", got)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != "gui-token.firstrun" {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("expected only gui-token.firstrun in the directory, got %v", names)
	}
}

// TestAnnounceFirstRun_TightensPreExistingFile — a stale .firstrun file from an older
// version, left at looser permissions, must not stay that way (same trap as
// SecureFile/SecureDir elsewhere in this codebase: os.WriteFile's mode only applies on
// create).
func TestAnnounceFirstRun_TightensPreExistingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "gui-token.firstrun")
	if err := os.WriteFile(path, []byte("stale"), 0644); err != nil {
		t.Fatalf("seed stale file: %v", err)
	}

	if err := AnnounceFirstRun(dir, "etcsec_gt_deadbeef"); err != nil {
		t.Fatalf("AnnounceFirstRun: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if got := info.Mode().Perm(); got != 0600 {
		t.Fatalf("pre-existing file left at %o, want 0600 tightened", got)
	}
}

func TestRedactTokens(t *testing.T) {
	token, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	t.Run("a real, freshly generated token is redacted", func(t *testing.T) {
		line := "some log line mentioning " + token + " inline"
		got := RedactTokens(line)
		if strings.Contains(got, token) {
			t.Fatalf("token survived redaction: %s", got)
		}
		if !strings.Contains(got, "[REDACTED:gui-token]") {
			t.Fatalf("expected a redaction marker, got: %s", got)
		}
	})

	t.Run("text without a token is untouched", func(t *testing.T) {
		line := "nothing sensitive here"
		if got := RedactTokens(line); got != line {
			t.Fatalf("got %q, want unchanged %q", got, line)
		}
	})

	t.Run("a rotated token this instance no longer holds is still caught by format", func(t *testing.T) {
		// This is the whole point of a format-based check alongside the value-based
		// one in internal/saas: an OLD token, already rotated via `gui-token reset`,
		// isn't in memory anywhere anymore, but its shape is still recognizable.
		oldToken, err := Generate()
		if err != nil {
			t.Fatalf("Generate: %v", err)
		}
		line := "leftover from an older binary: " + oldToken
		got := RedactTokens(line)
		if strings.Contains(got, oldToken) {
			t.Fatalf("rotated token survived redaction: %s", got)
		}
	})
}
