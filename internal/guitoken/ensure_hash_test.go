package guitoken

import "testing"

// TestEnsureHash_GeneratesWhenMissing — T_041/B_040. Making the admin API fail-closed
// on a missing hash only works if something generates one on startup; otherwise every
// collector upgraded (rather than reinstalled) before gui-token existed locks itself
// out of its own admin API.
func TestEnsureHash_GeneratesWhenMissing(t *testing.T) {
	dir := t.TempDir()

	hash, plaintext, generated, err := EnsureHash(dir)
	if err != nil {
		t.Fatalf("EnsureHash: %v", err)
	}
	if !generated {
		t.Fatal("expected a fresh token to be generated for an empty directory")
	}
	if plaintext == "" {
		t.Fatal("expected the plaintext token to be returned when a new one is generated")
	}
	if hash != Hash(plaintext) {
		t.Fatal("returned hash does not match the returned plaintext token")
	}
	if !Exists(dir) {
		t.Fatal("EnsureHash must persist the generated hash to disk")
	}
	if got := LoadHash(dir); got != hash {
		t.Fatalf("persisted hash %q does not match returned hash %q", got, hash)
	}
}

// TestEnsureHash_ReusesExisting — an already-configured install (or one where a prior
// EnsureHash call already ran) must not get a silently rotated token on every restart.
func TestEnsureHash_ReusesExisting(t *testing.T) {
	dir := t.TempDir()

	token, err := Generate()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	existingHash := Hash(token)
	if err := SaveHash(dir, existingHash); err != nil {
		t.Fatalf("save hash: %v", err)
	}

	hash, plaintext, generated, err := EnsureHash(dir)
	if err != nil {
		t.Fatalf("EnsureHash: %v", err)
	}
	if generated {
		t.Fatal("must not regenerate when a hash already exists")
	}
	if plaintext != "" {
		t.Fatal("must not return a plaintext token when reusing an existing hash")
	}
	if hash != existingHash {
		t.Fatalf("got hash %q, want existing %q", hash, existingHash)
	}
}
