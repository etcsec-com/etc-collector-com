package saas

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// commandStoreFileName is the on-disk file that persists executed command IDs
// across daemon restarts. Located under <dataDir>/state/.
const commandStoreFileName = "executed-commands.json"

// commandStoreRetention controls how long a record stays in the store. After
// this delay, entries are pruned at the next Save. SaaS commands have a much
// shorter TTL than 6h on the queue side, so this leaves comfortable margin for
// re-popped commands while keeping the file bounded.
const commandStoreRetention = 6 * time.Hour

// commandRecord captures a single executed command. We keep more than just the
// ID so the file is human-debuggable when triaging crash-loops on a host.
type commandRecord struct {
	ID          string    `json:"id"`
	Type        string    `json:"type"`
	StartedAt   time.Time `json:"started_at"`
	CompletedAt time.Time `json:"completed_at,omitzero"`
	Status      string    `json:"status"` // "started" (mark-before-exec) | "success" | "error"
}

// commandStore persists the set of executed command IDs to disk so a daemon
// restart (panic, OOM, in-place exec) does not re-execute the same command.
//
// Architectural note: this fixes the v3.1.x crash-loop where an UPDATE_COLLECTOR
// command would be retried indefinitely after a daemon restart, because the
// in-memory dedup map was cleared on every boot. The fix is twofold:
//
//  1. Persist to disk (this type) so the dedup outlives restarts.
//  2. Mark the command "started" BEFORE running it (Reserve), not after.
//     If the command crashes the daemon mid-exec, the next boot still sees the
//     ID and skips it — the SaaS knows about the failure via submitError or
//     the absence of a result, but the host stops self-destructing.
type commandStore struct {
	mu      sync.Mutex
	path    string
	records map[string]commandRecord
}

// newCommandStore loads (or initializes) the store at <stateDir>/<file>.
// Returns an empty store if the file is missing or unreadable. Corrupt files
// are silently reset — losing dedup history is preferable to refusing to start.
func newCommandStore(stateDir string) (*commandStore, error) {
	if err := os.MkdirAll(stateDir, 0700); err != nil {
		return nil, fmt.Errorf("create state dir: %w", err)
	}
	s := &commandStore{
		path:    filepath.Join(stateDir, commandStoreFileName),
		records: make(map[string]commandRecord),
	}
	s.load()
	return s, nil
}

// load reads the file from disk. Best-effort: a missing/corrupt file resets to
// an empty store. Caller must hold s.mu (or be in the constructor).
func (s *commandStore) load() {
	data, err := os.ReadFile(s.path)
	if err != nil {
		return
	}
	var disk struct {
		Records []commandRecord `json:"executed"`
	}
	if err := json.Unmarshal(data, &disk); err != nil {
		return
	}
	for _, r := range disk.Records {
		if r.ID == "" {
			continue
		}
		s.records[r.ID] = r
	}
}

// save writes the store atomically (tmp + rename). Caller must hold s.mu.
// Prunes records older than commandStoreRetention before writing.
func (s *commandStore) save() error {
	s.pruneLocked()

	records := make([]commandRecord, 0, len(s.records))
	for _, r := range s.records {
		records = append(records, r)
	}
	sort.Slice(records, func(i, j int) bool {
		return records[i].StartedAt.Before(records[j].StartedAt)
	})

	disk := struct {
		Records []commandRecord `json:"executed"`
	}{Records: records}

	data, err := json.MarshalIndent(disk, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	tmp := s.path + ".new"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return fmt.Errorf("write tmp: %w", err)
	}
	if err := os.Rename(tmp, s.path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("rename: %w", err)
	}
	return nil
}

// pruneLocked drops records older than retention. Caller must hold s.mu.
func (s *commandStore) pruneLocked() {
	cutoff := time.Now().Add(-commandStoreRetention)
	for id, r := range s.records {
		if r.StartedAt.Before(cutoff) {
			delete(s.records, id)
		}
	}
}

// Has reports whether a command ID is already known to the store. The dedup
// happens regardless of completion status — a "started" record blocks re-exec
// just as much as a "success" one (this is the crash-loop defense).
func (s *commandStore) Has(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.records[id]
	return ok
}

// Reserve marks a command as "started" BEFORE the daemon runs it and persists
// to disk. If the daemon crashes mid-exec, the next boot will see the record
// and skip the command instead of re-running it forever.
func (s *commandStore) Reserve(id, cmdType string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.records[id]; ok {
		return nil // already reserved/done — no-op
	}
	s.records[id] = commandRecord{
		ID:        id,
		Type:      cmdType,
		StartedAt: time.Now().UTC(),
		Status:    "started",
	}
	return s.save()
}

// Complete marks a previously-Reserved command as finished. status is "success"
// or "error" (free-form, just for human debugging — Has() is the source of
// truth for dedup). Best-effort: a Save error is logged by the caller.
func (s *commandStore) Complete(id, status string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.records[id]
	if !ok {
		// Reserve was somehow skipped — record now so we still dedup.
		r = commandRecord{
			ID:        id,
			StartedAt: time.Now().UTC(),
		}
	}
	r.CompletedAt = time.Now().UTC()
	r.Status = status
	s.records[id] = r
	return s.save()
}
