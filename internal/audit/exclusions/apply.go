package exclusions

import (
	"strings"

	"github.com/etcsec-com/etc-collector/pkg/types"
)

// DataLike abstracts the fields of audit.DetectorData we filter on. We use
// this interface instead of importing audit directly so the exclusions package
// stays free of import cycles (audit imports exclusions, not the other way).
type DataLike interface {
	GetUsers() []types.User
	SetUsers([]types.User)
	GetGroups() []types.Group
	SetGroups([]types.Group)
	GetComputers() []types.Computer
	SetComputers([]types.Computer)
	GetOUs() []types.OU
	SetOUs([]types.OU)
}

// ApplyToData filters users, computers, groups and OUs in place on data
// according to cfg. Returns a Report with per-type counts + reasons. If cfg is
// nil or empty, returns an empty report and data is unchanged.
//
// NOTE: callers should also filter downstream collections that reference DNs
// removed here (ACLEntries, ObjectOwners). See ScrubDNReferences.
func ApplyToData(data DataLike, cfg *Config) *Report {
	report := &Report{
		RulesVersion: 1,
		AssetCounts:  map[string]*Counts{},
	}
	if cfg == nil || cfg.compiled == nil {
		return report
	}
	report.RulesHash = cfg.Hash
	report.RulesVersion = cfg.Version

	// Users
	if rules := cfg.compiled.users; rules != nil {
		users, counts := filterUsers(data.GetUsers(), rules)
		data.SetUsers(users)
		report.AssetCounts["users"] = counts
	} else {
		report.AssetCounts["users"] = passthroughCounts(len(data.GetUsers()))
	}

	// Computers
	if rules := cfg.compiled.computers; rules != nil {
		computers, counts := filterComputers(data.GetComputers(), rules)
		data.SetComputers(computers)
		report.AssetCounts["computers"] = counts
	} else {
		report.AssetCounts["computers"] = passthroughCounts(len(data.GetComputers()))
	}

	// Groups
	if rules := cfg.compiled.groups; rules != nil {
		groups, counts := filterGroups(data.GetGroups(), rules)
		data.SetGroups(groups)
		report.AssetCounts["groups"] = counts
	} else {
		report.AssetCounts["groups"] = passthroughCounts(len(data.GetGroups()))
	}

	// OUs
	if rules := cfg.compiled.ous; rules != nil {
		ous, counts := filterOUs(data.GetOUs(), rules)
		data.SetOUs(ous)
		report.AssetCounts["ous"] = counts
	} else {
		report.AssetCounts["ous"] = passthroughCounts(len(data.GetOUs()))
	}

	return report
}

func passthroughCounts(n int) *Counts {
	return &Counts{Total: n, Scanned: n, Excluded: 0}
}

// shouldKeep applies include+exclude semantics for a single object. Returns
// (keep, reason). reason is populated only when keep==false.
func shouldKeep(rules *compiledAssetRules, dn, sam, host, name string) (bool, hitReason) {
	if rules == nil {
		return true, hitReason{}
	}
	// scope: if any scope prefixes are declared, the DN must sit under one of them.
	if len(rules.scope) > 0 {
		ndn := normaliseDN(dn)
		inScope := false
		for _, s := range rules.scope {
			if dnUnder(ndn, s) {
				inScope = true
				break
			}
		}
		if !inScope {
			return false, hitReason{Field: "scope", Pattern: strings.Join(rules.scope, ",")}
		}
	}
	// include: when declared, must match at least one rule.
	if rules.include != nil {
		ok, _ := matchFilter(rules.include, dn, sam, host, name)
		if !ok {
			return false, hitReason{Field: "include", Pattern: "no-match"}
		}
	}
	// exclude: if matched, drop the object.
	if rules.exclude != nil {
		ok, r := matchFilter(rules.exclude, dn, sam, host, name)
		if ok {
			return false, r
		}
	}
	return true, hitReason{}
}

func filterUsers(users []types.User, rules *compiledAssetRules) ([]types.User, *Counts) {
	counts := &Counts{Total: len(users)}
	if rules == nil {
		counts.Scanned = len(users)
		return users, counts
	}
	kept := users[:0]
	for _, u := range users {
		keep, reason := shouldKeep(rules, u.DN, userSam(u), "", "")
		if keep {
			kept = append(kept, u)
			continue
		}
		counts.Excluded++
		counts.Reasons = bumpReason(counts.Reasons, reason, u.DN)
	}
	counts.Scanned = counts.Total - counts.Excluded
	// Return a fresh slice so the caller doesn't silently share backing memory.
	out := make([]types.User, len(kept))
	copy(out, kept)
	return out, counts
}

func filterComputers(computers []types.Computer, rules *compiledAssetRules) ([]types.Computer, *Counts) {
	counts := &Counts{Total: len(computers)}
	if rules == nil {
		counts.Scanned = len(computers)
		return computers, counts
	}
	kept := computers[:0]
	for _, c := range computers {
		keep, reason := shouldKeep(rules, c.DN, computerSam(c), computerHostname(c), "")
		if keep {
			kept = append(kept, c)
			continue
		}
		counts.Excluded++
		counts.Reasons = bumpReason(counts.Reasons, reason, c.DN)
	}
	counts.Scanned = counts.Total - counts.Excluded
	out := make([]types.Computer, len(kept))
	copy(out, kept)
	return out, counts
}

func filterGroups(groups []types.Group, rules *compiledAssetRules) ([]types.Group, *Counts) {
	counts := &Counts{Total: len(groups)}
	if rules == nil {
		counts.Scanned = len(groups)
		return groups, counts
	}
	kept := groups[:0]
	for _, g := range groups {
		keep, reason := shouldKeep(rules, g.DN, groupSam(g), "", groupName(g))
		if keep {
			kept = append(kept, g)
			continue
		}
		counts.Excluded++
		counts.Reasons = bumpReason(counts.Reasons, reason, g.DN)
	}
	counts.Scanned = counts.Total - counts.Excluded
	out := make([]types.Group, len(kept))
	copy(out, kept)
	return out, counts
}

func filterOUs(ous []types.OU, rules *compiledAssetRules) ([]types.OU, *Counts) {
	counts := &Counts{Total: len(ous)}
	if rules == nil {
		counts.Scanned = len(ous)
		return ous, counts
	}
	kept := ous[:0]
	for _, o := range ous {
		keep, reason := shouldKeep(rules, o.DN, "", "", ouName(o))
		if keep {
			kept = append(kept, o)
			continue
		}
		counts.Excluded++
		counts.Reasons = bumpReason(counts.Reasons, reason, o.DN)
	}
	counts.Scanned = counts.Total - counts.Excluded
	out := make([]types.OU, len(kept))
	copy(out, kept)
	return out, counts
}

// ScrubDNReferences removes ACL entries and owner map entries whose ObjectDN
// is not in the keepDNs set. Called by the engine after ApplyToData so
// downstream detectors don't see findings on excluded assets.
func ScrubDNReferences(acls []types.ACLEntry, owners map[string]string, keepDNs map[string]struct{}) ([]types.ACLEntry, map[string]string) {
	if len(keepDNs) == 0 {
		return acls, owners
	}
	trimmedACLs := acls[:0]
	for _, a := range acls {
		if _, ok := keepDNs[normaliseDN(a.ObjectDN)]; ok {
			trimmedACLs = append(trimmedACLs, a)
		}
	}
	outACLs := make([]types.ACLEntry, len(trimmedACLs))
	copy(outACLs, trimmedACLs)

	outOwners := make(map[string]string, len(owners))
	for dn, sid := range owners {
		if _, ok := keepDNs[normaliseDN(dn)]; ok {
			outOwners[dn] = sid
		}
	}
	return outACLs, outOwners
}

// ApplyPerDetector returns a filtered clone of data for the given detectorID.
// Only assets matching a DetectorRule.Scope filter for this detector are
// removed (the originals remain in the caller's data; other detectors see
// them). Returns the filtered DataLike-compatible snapshot fields and a
// DetectorExclusion slice describing what was dropped.
//
// The detector engine decides whether to use these filtered slices or the
// originals when calling each detector's Detect method.
func ApplyPerDetector(cfg *Config, detectorID string, data DataLike) (users []types.User, computers []types.Computer, groups []types.Group, ous []types.OU, excl []DetectorExclusion) {
	users = data.GetUsers()
	computers = data.GetComputers()
	groups = data.GetGroups()
	ous = data.GetOUs()
	if cfg == nil || cfg.compiled == nil {
		return
	}
	for _, d := range cfg.compiled.detectors {
		if d.id != detectorID {
			continue
		}
		if d.users != nil {
			users, excl = applyDetectorUsers(users, d, excl)
		}
		if d.computers != nil {
			computers, excl = applyDetectorComputers(computers, d, excl)
		}
		if d.groups != nil {
			groups, excl = applyDetectorGroups(groups, d, excl)
		}
		if d.ous != nil {
			ous, excl = applyDetectorOUs(ous, d, excl)
		}
	}
	return
}

func applyDetectorUsers(users []types.User, d compiledDetectorRule, excl []DetectorExclusion) ([]types.User, []DetectorExclusion) {
	kept := users[:0]
	entry := DetectorExclusion{DetectorID: d.id, Reason: d.reason, Scope: "users"}
	for _, u := range users {
		ok, _ := matchFilter(d.users, u.DN, userSam(u), "", "")
		if ok {
			entry.Matched++
			if len(entry.SampleDNs) < maxSampleDNs {
				entry.SampleDNs = append(entry.SampleDNs, u.DN)
			}
			continue
		}
		kept = append(kept, u)
	}
	out := make([]types.User, len(kept))
	copy(out, kept)
	if entry.Matched > 0 {
		excl = append(excl, entry)
	}
	return out, excl
}

func applyDetectorComputers(computers []types.Computer, d compiledDetectorRule, excl []DetectorExclusion) ([]types.Computer, []DetectorExclusion) {
	kept := computers[:0]
	entry := DetectorExclusion{DetectorID: d.id, Reason: d.reason, Scope: "computers"}
	for _, c := range computers {
		ok, _ := matchFilter(d.computers, c.DN, computerSam(c), computerHostname(c), "")
		if ok {
			entry.Matched++
			if len(entry.SampleDNs) < maxSampleDNs {
				entry.SampleDNs = append(entry.SampleDNs, c.DN)
			}
			continue
		}
		kept = append(kept, c)
	}
	out := make([]types.Computer, len(kept))
	copy(out, kept)
	if entry.Matched > 0 {
		excl = append(excl, entry)
	}
	return out, excl
}

func applyDetectorGroups(groups []types.Group, d compiledDetectorRule, excl []DetectorExclusion) ([]types.Group, []DetectorExclusion) {
	kept := groups[:0]
	entry := DetectorExclusion{DetectorID: d.id, Reason: d.reason, Scope: "groups"}
	for _, g := range groups {
		ok, _ := matchFilter(d.groups, g.DN, groupSam(g), "", groupName(g))
		if ok {
			entry.Matched++
			if len(entry.SampleDNs) < maxSampleDNs {
				entry.SampleDNs = append(entry.SampleDNs, g.DN)
			}
			continue
		}
		kept = append(kept, g)
	}
	out := make([]types.Group, len(kept))
	copy(out, kept)
	if entry.Matched > 0 {
		excl = append(excl, entry)
	}
	return out, excl
}

func applyDetectorOUs(ous []types.OU, d compiledDetectorRule, excl []DetectorExclusion) ([]types.OU, []DetectorExclusion) {
	kept := ous[:0]
	entry := DetectorExclusion{DetectorID: d.id, Reason: d.reason, Scope: "ous"}
	for _, o := range ous {
		ok, _ := matchFilter(d.ous, o.DN, "", "", ouName(o))
		if ok {
			entry.Matched++
			if len(entry.SampleDNs) < maxSampleDNs {
				entry.SampleDNs = append(entry.SampleDNs, o.DN)
			}
			continue
		}
		kept = append(kept, o)
	}
	out := make([]types.OU, len(kept))
	copy(out, kept)
	if entry.Matched > 0 {
		excl = append(excl, entry)
	}
	return out, excl
}

// FilterDNs keeps only DNs that pass the whole-asset filters for their type.
// Used by the engine to prune objectDNs before GetACLs.
func FilterDNs(cfg *Config, dns []string, assetType string) []string {
	if cfg == nil || cfg.compiled == nil {
		return dns
	}
	var rules *compiledAssetRules
	switch assetType {
	case "users":
		rules = cfg.compiled.users
	case "computers":
		rules = cfg.compiled.computers
	case "groups":
		rules = cfg.compiled.groups
	case "ous":
		rules = cfg.compiled.ous
	}
	if rules == nil {
		return dns
	}
	out := dns[:0]
	for _, dn := range dns {
		keep, _ := shouldKeep(rules, dn, "", "", "")
		if keep {
			out = append(out, dn)
		}
	}
	result := make([]string, len(out))
	copy(result, out)
	return result
}
