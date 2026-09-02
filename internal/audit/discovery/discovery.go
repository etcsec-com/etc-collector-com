// Package discovery lists AD assets (OUs, users, computers, groups) without
// running detectors. Used by the `etc-collector discover ad` CLI and the SaaS
// DISCOVER_AD command so an auditor can review the domain inventory before
// configuring asset filters (see internal/audit/exclusions).
package discovery

import (
	"context"
	"sort"
	"strings"
	"time"

	"github.com/etcsec-com/etc-collector/internal/providers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// LDAPLike is the subset of the LDAP provider discovery needs. Kept minimal
// so the daemon and CLI can share the same code path without depending on the
// audit engine.
type LDAPLike interface {
	GetUsers(ctx context.Context, opts providers.QueryOptions) ([]types.User, error)
	GetGroups(ctx context.Context, opts providers.QueryOptions) ([]types.Group, error)
	GetComputers(ctx context.Context, opts providers.QueryOptions) ([]types.Computer, error)
	GetOUs(ctx context.Context, opts providers.QueryOptions) ([]types.OU, error)
	GetDomainInfo(ctx context.Context) (*types.DomainInfo, error)
}

// Options configures a discovery run.
type Options struct {
	// SampleSize caps the number of DN samples returned per asset type (default 50).
	// Ignored when FullListing is true.
	SampleSize int

	// FullListing, when true, returns every user/computer/group/OU in the
	// manifest samples instead of a bounded sample. Enables SaaS / CLI UIs to
	// build per-asset checkboxes (e.g. "exclude this specific service
	// account") on top of the manifest. Large domains: 100k users ≈ ~10 MB
	// JSON (~2 MB gzipped) — acceptable for opt-in use.
	FullListing bool

	// IncludeGroupMembers, when set, controls whether each GroupSample gets
	// its `member` attribute expanded into the Members field. Nil means
	// "default to FullListing"; set to a pointer-to-true/false to override.
	// Direct members only — transitive resolution is the caller's job.
	IncludeGroupMembers *bool

	// Progress, if non-nil, is called after each collection phase so the
	// caller can emit intermediate command results (progress bar, etc.).
	// Never called with a nil Manifest; Counts is always populated, Samples
	// are populated progressively.
	Progress func(evt ProgressEvent)
}

// ProgressEvent is fired at key phases of discovery. EstimatedRemainingMs is a
// crude extrapolation from the time spent so far; treat it as a hint, not a
// contract.
type ProgressEvent struct {
	Phase                string       `json:"phase"` // "fetching_users" | "users_done" | "groups_done" | "computers_done" | "ous_done" | "done"
	Counts               CountsByType `json:"counts"`
	ElapsedMs            int64        `json:"elapsedMs"`
	EstimatedRemainingMs int64        `json:"estimatedRemainingMs,omitempty"`
	ExpectedTotalAssets  int          `json:"expectedTotalAssets,omitempty"` // set once all fetches complete
}

// Manifest is the output of a discovery run: counts + OU tree + sample DNs.
// Serialised as JSON and consumed by auditors / the SaaS UI to build an
// exclusions.yaml config.
type Manifest struct {
	Version     int           `json:"version"`
	GeneratedAt time.Time     `json:"generatedAt"`
	Domain      string        `json:"domain,omitempty"`
	Counts      CountsByType  `json:"counts"`
	OUTree      []OUBranch    `json:"ouTree,omitempty"`
	Samples     SamplesByType `json:"samples"`
}

// CountsByType gives the total number of each asset type in the domain.
type CountsByType struct {
	Users     int `json:"users"`
	Groups    int `json:"groups"`
	Computers int `json:"computers"`
	OUs       int `json:"ous"`
}

// SamplesByType holds up to SampleSize objects per type — enough for the
// auditor to pick representative DNs / patterns.
type SamplesByType struct {
	Users     []UserSample     `json:"users,omitempty"`
	Groups    []GroupSample    `json:"groups,omitempty"`
	Computers []ComputerSample `json:"computers,omitempty"`
	OUs       []OUSample       `json:"ous,omitempty"`
}

// UserSample is a compact user DN entry.
type UserSample struct {
	DN         string `json:"dn"`
	SAM        string `json:"sAMAccountName,omitempty"`
	ParentOuDN string `json:"parentOuDN,omitempty"`
}

// GroupSample is a compact group DN entry. Members is populated when
// Options.IncludeGroupMembers is true (defaults to Options.FullListing).
// A pointer to a slice is used so the field renders as "members": [] for an
// empty group (non-nil slice) and is omitted entirely when not requested
// (nil pointer) — the SaaS UI relies on this to tell "no members" apart
// from "not computed".
type GroupSample struct {
	DN         string    `json:"dn"`
	SAM        string    `json:"sAMAccountName,omitempty"`
	ParentOuDN string    `json:"parentOuDN,omitempty"`
	Members    *[]string `json:"members,omitempty"`
}

// ComputerSample is a compact computer DN entry.
type ComputerSample struct {
	DN         string `json:"dn"`
	Hostname   string `json:"dNSHostName,omitempty"`
	OS         string `json:"operatingSystem,omitempty"`
	ParentOuDN string `json:"parentOuDN,omitempty"`
}

// OUSample is a compact OU DN entry.
type OUSample struct {
	DN         string `json:"dn"`
	Name       string `json:"name,omitempty"`
	ParentOuDN string `json:"parentOuDN,omitempty"`
}

// OUBranch is a node in the OU tree. Children are other OUBranch entries.
// Counts show how many users/computers live directly under this DN (not
// recursively — the auditor sees the distribution per node).
type OUBranch struct {
	DN     string `json:"dn"`
	Name   string `json:"name"`
	Counts struct {
		Users     int `json:"users"`
		Computers int `json:"computers"`
	} `json:"counts"`
	Children []OUBranch `json:"children,omitempty"`
}

// Run fetches the inventory from the LDAP provider and returns a Manifest.
// When opts.FullListing is true, samples contain every object; otherwise
// SampleSize (default 50) caps each type.
// When opts.Progress is non-nil it is called after each major phase so the
// caller can relay progress events (SaaS progress bar, CLI logs).
func Run(ctx context.Context, p LDAPLike, opts Options) (*Manifest, error) {
	if opts.SampleSize <= 0 {
		opts.SampleSize = 50
	}
	start := time.Now()
	emit := func(phase string, expected int, counts CountsByType) {
		if opts.Progress == nil {
			return
		}
		elapsed := time.Since(start).Milliseconds()
		evt := ProgressEvent{
			Phase:     phase,
			Counts:    counts,
			ElapsedMs: elapsed,
		}
		if expected > 0 {
			evt.ExpectedTotalAssets = expected
		}
		// Crude remaining estimator: once we know users, extrapolate linearly
		// based on the fraction of total assets already fetched.
		done := counts.Users + counts.Groups + counts.Computers + counts.OUs
		if expected > 0 && done > 0 && done < expected && elapsed > 0 {
			evt.EstimatedRemainingMs = elapsed * int64(expected-done) / int64(done)
		}
		opts.Progress(evt)
	}

	m := &Manifest{
		Version:     1,
		GeneratedAt: time.Now().UTC(),
	}

	if di, err := p.GetDomainInfo(ctx); err == nil && di != nil {
		m.Domain = di.DomainName
		if m.Domain == "" {
			m.Domain = di.ForestName
		}
	}

	emit("fetching_users", 0, m.Counts)

	users, err := p.GetUsers(ctx, providers.QueryOptions{})
	if err != nil {
		return nil, err
	}
	m.Counts.Users = len(users)
	emit("users_done", 0, m.Counts)

	groups, err := p.GetGroups(ctx, providers.QueryOptions{})
	if err != nil {
		return nil, err
	}
	m.Counts.Groups = len(groups)
	emit("groups_done", 0, m.Counts)

	computers, err := p.GetComputers(ctx, providers.QueryOptions{})
	if err != nil {
		return nil, err
	}
	m.Counts.Computers = len(computers)
	emit("computers_done", 0, m.Counts)

	ous, err := p.GetOUs(ctx, providers.QueryOptions{})
	if err != nil {
		return nil, err
	}
	m.Counts.OUs = len(ous)
	expected := m.Counts.Users + m.Counts.Groups + m.Counts.Computers + m.Counts.OUs
	emit("ous_done", expected, m.Counts)

	// Build samples (all or capped).
	limit := opts.SampleSize
	if opts.FullListing {
		limit = -1 // unlimited
	}
	includeMembers := opts.FullListing
	if opts.IncludeGroupMembers != nil {
		includeMembers = *opts.IncludeGroupMembers
	}
	m.Samples.Users = sampleUsers(users, limit)
	m.Samples.Groups = sampleGroups(groups, limit, includeMembers)
	m.Samples.Computers = sampleComputers(computers, limit)
	m.Samples.OUs = sampleOUs(ous, limit)

	m.OUTree = buildOUTree(ous, users, computers)

	emit("done", expected, m.Counts)
	return m, nil
}

// capCount returns how many items to emit given the raw slice length and the
// caller-provided limit. limit < 0 means "all"; limit == 0 falls back to the
// default (handled at Run entry).
func capCount(have, limit int) int {
	if limit < 0 || limit > have {
		return have
	}
	return limit
}

func sampleUsers(users []types.User, limit int) []UserSample {
	n := capCount(len(users), limit)
	out := make([]UserSample, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, UserSample{
			DN:         users[i].DN,
			SAM:        users[i].SAMAccountName,
			ParentOuDN: parentDN(users[i].DN),
		})
	}
	return out
}

func sampleGroups(groups []types.Group, limit int, includeMembers bool) []GroupSample {
	n := capCount(len(groups), limit)
	out := make([]GroupSample, 0, n)
	for i := 0; i < n; i++ {
		sample := GroupSample{
			DN:         groups[i].DN,
			SAM:        groups[i].SAMAccountName,
			ParentOuDN: parentDN(groups[i].DN),
		}
		if includeMembers {
			// Defensive copy so downstream mutation of Members doesn't leak
			// back into the source slice owned by the provider cache.
			// Always non-nil — an empty-but-non-nil slice renders "members":[]
			// so the SaaS UI can distinguish "empty group" from "not requested".
			members := append([]string(nil), groups[i].Members...)
			if members == nil {
				members = []string{}
			}
			sample.Members = &members
		}
		out = append(out, sample)
	}
	return out
}

func sampleComputers(computers []types.Computer, limit int) []ComputerSample {
	n := capCount(len(computers), limit)
	out := make([]ComputerSample, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, ComputerSample{
			DN:         computers[i].DN,
			Hostname:   computers[i].DNSHostName,
			OS:         computers[i].OperatingSystem,
			ParentOuDN: parentDN(computers[i].DN),
		})
	}
	return out
}

func sampleOUs(ous []types.OU, limit int) []OUSample {
	n := capCount(len(ous), limit)
	out := make([]OUSample, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, OUSample{
			DN:         ous[i].DN,
			Name:       ous[i].Name,
			ParentOuDN: parentDN(ous[i].DN),
		})
	}
	return out
}

// buildOUTree constructs a recursive tree of OUs with per-node user/computer
// counts (immediate children, not recursive). OUs are sorted by DN depth
// (shortest first) so parents are inserted before children.
func buildOUTree(ous []types.OU, users []types.User, computers []types.Computer) []OUBranch {
	// Sort by DN component count (shallowest first) for deterministic output.
	sorted := make([]types.OU, len(ous))
	copy(sorted, ous)
	sort.Slice(sorted, func(i, j int) bool {
		return dnDepth(sorted[i].DN) < dnDepth(sorted[j].DN)
	})

	nodes := make(map[string]*OUBranch, len(sorted))
	var roots []*OUBranch
	for i := range sorted {
		node := &OUBranch{DN: sorted[i].DN, Name: sorted[i].Name}
		nodes[strings.ToLower(sorted[i].DN)] = node
		parent := parentDN(sorted[i].DN)
		if p, ok := nodes[strings.ToLower(parent)]; ok {
			p.Children = append(p.Children, *node)
		} else {
			roots = append(roots, node)
		}
	}

	// Populate immediate child counts.
	for _, u := range users {
		if p, ok := nodes[strings.ToLower(parentDN(u.DN))]; ok {
			p.Counts.Users++
		}
	}
	for _, c := range computers {
		if p, ok := nodes[strings.ToLower(parentDN(c.DN))]; ok {
			p.Counts.Computers++
		}
	}

	out := make([]OUBranch, 0, len(roots))
	for _, r := range roots {
		out = append(out, *r)
	}
	return out
}

// parentDN returns the parent DN of a DN (the DN minus the first RDN).
// e.g. "CN=Foo,OU=Bar,DC=x" → "OU=Bar,DC=x".
func parentDN(dn string) string {
	if idx := strings.Index(dn, ","); idx >= 0 {
		return strings.TrimSpace(dn[idx+1:])
	}
	return ""
}

// dnDepth returns the number of comma-separated RDN components in a DN.
func dnDepth(dn string) int {
	if dn == "" {
		return 0
	}
	return strings.Count(dn, ",") + 1
}
