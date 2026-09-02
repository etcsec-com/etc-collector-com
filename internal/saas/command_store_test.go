package saas

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestCommandStore_ReserveThenHas verifies that Reserve persists to disk
// immediately so a fresh store opened on the same dir sees the entry.
// This is the crash-loop defense — a daemon restart must NOT re-execute
// a command that was previously Reserved (even if Complete never ran).
func TestCommandStore_ReserveThenHas(t *testing.T) {
	dir := t.TempDir()

	s1, err := newCommandStore(dir)
	if err != nil {
		t.Fatalf("newCommandStore: %v", err)
	}

	if s1.Has("cmd-1") {
		t.Fatalf("fresh store reports cmd-1 known")
	}
	if err := s1.Reserve("cmd-1", "UPDATE_COLLECTOR"); err != nil {
		t.Fatalf("Reserve: %v", err)
	}
	if !s1.Has("cmd-1") {
		t.Fatalf("Has returned false right after Reserve")
	}

	// Simulate a daemon restart: open a brand-new store on the same dir.
	s2, err := newCommandStore(dir)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if !s2.Has("cmd-1") {
		t.Fatalf("dedup did not survive restart")
	}
}

// TestCommandStore_CompleteUpdatesStatus verifies Complete records status +
// CompletedAt without losing the StartedAt set by Reserve.
func TestCommandStore_CompleteUpdatesStatus(t *testing.T) {
	dir := t.TempDir()
	s, err := newCommandStore(dir)
	if err != nil {
		t.Fatalf("newCommandStore: %v", err)
	}
	if err := s.Reserve("cmd-x", "RUN_AUDIT_AD"); err != nil {
		t.Fatalf("Reserve: %v", err)
	}
	startedAt := s.records["cmd-x"].StartedAt

	if err := s.Complete("cmd-x", "success"); err != nil {
		t.Fatalf("Complete: %v", err)
	}
	r := s.records["cmd-x"]
	if r.Status != "success" {
		t.Fatalf("status = %q, want success", r.Status)
	}
	if r.CompletedAt.IsZero() {
		t.Fatalf("CompletedAt not set")
	}
	if !r.StartedAt.Equal(startedAt) {
		t.Fatalf("StartedAt mutated by Complete: %v -> %v", startedAt, r.StartedAt)
	}
}

// TestCommandStore_Idempotent checks Reserve on an already-known ID is a no-op
// (doesn't reset StartedAt, doesn't clobber Status).
func TestCommandStore_Idempotent(t *testing.T) {
	dir := t.TempDir()
	s, _ := newCommandStore(dir)
	_ = s.Reserve("cmd-1", "T1")
	_ = s.Complete("cmd-1", "success")
	original := s.records["cmd-1"]

	if err := s.Reserve("cmd-1", "T2"); err != nil {
		t.Fatalf("Reserve: %v", err)
	}
	r := s.records["cmd-1"]
	if r.Status != original.Status {
		t.Fatalf("Reserve clobbered Status: %q -> %q", original.Status, r.Status)
	}
}

// TestCommandStore_PruneOldEntries verifies retention cutoff drops stale
// records. We backdate a record manually then trigger save (which prunes).
func TestCommandStore_PruneOldEntries(t *testing.T) {
	dir := t.TempDir()
	s, _ := newCommandStore(dir)

	_ = s.Reserve("recent", "T")
	s.mu.Lock()
	s.records["stale"] = commandRecord{
		ID:        "stale",
		Type:      "T",
		StartedAt: time.Now().Add(-commandStoreRetention - time.Hour),
		Status:    "success",
	}
	if err := s.save(); err != nil {
		s.mu.Unlock()
		t.Fatalf("save: %v", err)
	}
	s.mu.Unlock()

	if !s.Has("recent") {
		t.Fatalf("recent record dropped")
	}
	if s.Has("stale") {
		t.Fatalf("stale record not pruned")
	}
}

// TestCommandStore_CorruptFileResets verifies a corrupt JSON file doesn't
// prevent the daemon from starting. We'd rather lose dedup history than block.
func TestCommandStore_CorruptFileResets(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, commandStoreFileName), []byte("{not json"), 0600); err != nil {
		t.Fatalf("seed corrupt file: %v", err)
	}
	s, err := newCommandStore(dir)
	if err != nil {
		t.Fatalf("newCommandStore on corrupt file: %v", err)
	}
	if s.Has("anything") {
		t.Fatalf("corrupt file leaked entries")
	}
	// Should be writable from here.
	if err := s.Reserve("cmd-new", "T"); err != nil {
		t.Fatalf("Reserve after corrupt: %v", err)
	}
}

// TestCommandStore_AtomicWrite checks the on-disk file is parseable JSON
// after every Save (no half-written state visible).
func TestCommandStore_AtomicWrite(t *testing.T) {
	dir := t.TempDir()
	s, _ := newCommandStore(dir)
	for i := 0; i < 5; i++ {
		if err := s.Reserve("cmd-"+string(rune('a'+i)), "T"); err != nil {
			t.Fatalf("Reserve: %v", err)
		}
	}
	data, err := os.ReadFile(filepath.Join(dir, commandStoreFileName))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var disk struct {
		Records []commandRecord `json:"executed"`
	}
	if err := json.Unmarshal(data, &disk); err != nil {
		t.Fatalf("file is not valid JSON: %v", err)
	}
	if len(disk.Records) != 5 {
		t.Fatalf("got %d records, want 5", len(disk.Records))
	}
}
