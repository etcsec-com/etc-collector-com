package exclusions

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/etcsec-com/etc-collector/pkg/types"
)

// compiledConfig holds precompiled matchers for every scope. Built once at
// Load time so the hot path (ApplyToData) only does regex matching.
type compiledConfig struct {
	users     *compiledAssetRules
	computers *compiledAssetRules
	groups    *compiledAssetRules
	ous       *compiledAssetRules
	detectors []compiledDetectorRule
}

type compiledAssetRules struct {
	scope   []string        // normalised DN suffixes
	include *compiledFilter // nil = no include restriction
	exclude *compiledFilter // nil = no exclusions
}

type compiledFilter struct {
	dns              map[string]struct{} // normalised
	underOUs         []string            // normalised (always comma-prefixed suffix)
	samPatterns      []*regexp.Regexp
	hostnamePatterns []*regexp.Regexp
	namePatterns     []*regexp.Regexp
	regex            []*regexp.Regexp

	// Raw string forms, kept so the Report can cite the original rule.
	samPatternsRaw      []string
	hostnamePatternsRaw []string
	namePatternsRaw     []string
	regexRaw            []string
}

type compiledDetectorRule struct {
	id        string
	reason    string
	users     *compiledFilter
	computers *compiledFilter
	groups    *compiledFilter
	ous       *compiledFilter
}

// compile precomputes matchers for the whole Config. Must be called after
// Validate and before first use.
func (c *Config) compile() error {
	cc := &compiledConfig{}
	var err error
	if cc.users, err = compileAssetRules(c.Users); err != nil {
		return fmt.Errorf("users: %w", err)
	}
	if cc.computers, err = compileAssetRules(c.Computers); err != nil {
		return fmt.Errorf("computers: %w", err)
	}
	if cc.groups, err = compileAssetRules(c.Groups); err != nil {
		return fmt.Errorf("groups: %w", err)
	}
	if cc.ous, err = compileAssetRules(c.OUs); err != nil {
		return fmt.Errorf("ous: %w", err)
	}
	for i, d := range c.Detectors {
		cd := compiledDetectorRule{id: d.ID, reason: d.Reason}
		for scope, f := range d.Scope {
			cf, err := compileFilter(f)
			if err != nil {
				return fmt.Errorf("detectors[%d].scope.%s: %w", i, scope, err)
			}
			switch scope {
			case "users":
				cd.users = cf
			case "computers":
				cd.computers = cf
			case "groups":
				cd.groups = cf
			case "ous":
				cd.ous = cf
			}
		}
		cc.detectors = append(cc.detectors, cd)
	}
	c.compiled = cc
	return nil
}

func compileAssetRules(r *AssetRules) (*compiledAssetRules, error) {
	if r == nil {
		return nil, nil
	}
	out := &compiledAssetRules{}
	for _, s := range r.Scope {
		out.scope = append(out.scope, normaliseDN(s))
	}
	if r.Include != nil {
		cf, err := compileFilter(r.Include)
		if err != nil {
			return nil, fmt.Errorf("include: %w", err)
		}
		out.include = cf
	}
	if r.Exclude != nil {
		cf, err := compileFilter(r.Exclude)
		if err != nil {
			return nil, fmt.Errorf("exclude: %w", err)
		}
		out.exclude = cf
	}
	return out, nil
}

func compileFilter(f *Filter) (*compiledFilter, error) {
	if f == nil {
		return nil, nil
	}
	out := &compiledFilter{
		dns: make(map[string]struct{}, len(f.DNs)),
	}
	for _, dn := range f.DNs {
		out.dns[normaliseDN(dn)] = struct{}{}
	}
	for _, ou := range f.UnderOUs {
		out.underOUs = append(out.underOUs, normaliseDN(ou))
	}
	for _, p := range f.SamPatterns {
		rx, err := globToRegex(p)
		if err != nil {
			return nil, fmt.Errorf("sam_patterns[%q]: %w", p, err)
		}
		out.samPatterns = append(out.samPatterns, rx)
		out.samPatternsRaw = append(out.samPatternsRaw, p)
	}
	for _, p := range f.HostnamePatterns {
		rx, err := globToRegex(p)
		if err != nil {
			return nil, fmt.Errorf("hostname_patterns[%q]: %w", p, err)
		}
		out.hostnamePatterns = append(out.hostnamePatterns, rx)
		out.hostnamePatternsRaw = append(out.hostnamePatternsRaw, p)
	}
	for _, p := range f.NamePatterns {
		rx, err := globToRegex(p)
		if err != nil {
			return nil, fmt.Errorf("name_patterns[%q]: %w", p, err)
		}
		out.namePatterns = append(out.namePatterns, rx)
		out.namePatternsRaw = append(out.namePatternsRaw, p)
	}
	for _, rx := range f.Regex {
		r, err := regexp.Compile(rx)
		if err != nil {
			return nil, fmt.Errorf("regex[%q]: %w", rx, err)
		}
		out.regex = append(out.regex, r)
		out.regexRaw = append(out.regexRaw, rx)
	}
	return out, nil
}

// normaliseDN lowercases a DN and collapses whitespace around '=' and ','
// so that "CN = Foo , OU = Bar" matches "cn=foo,ou=bar".
func normaliseDN(dn string) string {
	dn = strings.TrimSpace(strings.ToLower(dn))
	var b strings.Builder
	b.Grow(len(dn))
	lastWasSep := false
	for i := 0; i < len(dn); i++ {
		c := dn[i]
		switch c {
		case ' ', '\t':
			// skip whitespace if we're right after or before a separator
			if lastWasSep {
				continue
			}
			// also skip whitespace before a separator
			// peek ahead
			j := i + 1
			for j < len(dn) && (dn[j] == ' ' || dn[j] == '\t') {
				j++
			}
			if j < len(dn) && (dn[j] == ',' || dn[j] == '=') {
				continue
			}
			// keep the space
			b.WriteByte(c)
			lastWasSep = false
		case ',', '=':
			b.WriteByte(c)
			lastWasSep = true
		default:
			b.WriteByte(c)
			lastWasSep = false
		}
	}
	return b.String()
}

// globToRegex converts a glob pattern with * and ? to an anchored, case-
// insensitive regexp. All other regex metacharacters are escaped.
func globToRegex(glob string) (*regexp.Regexp, error) {
	var b strings.Builder
	b.WriteString("(?i)^")
	for i := 0; i < len(glob); i++ {
		c := glob[i]
		switch c {
		case '*':
			b.WriteString(".*")
		case '?':
			b.WriteByte('.')
		case '.', '+', '(', ')', '[', ']', '{', '}', '^', '$', '|', '\\':
			b.WriteByte('\\')
			b.WriteByte(c)
		default:
			b.WriteByte(c)
		}
	}
	b.WriteByte('$')
	return regexp.Compile(b.String())
}

// hitReason describes why an object was matched by a filter. Used to populate
// the audit result's exclusions trail.
type hitReason struct {
	Field   string // "dn", "under_ou", "sam", "hostname", "name", "regex"
	Pattern string // the raw rule that matched
}

// matchFilter returns true and the match reason if obj matches at least one
// rule in f. The caller is responsible for calling with the right sam/hostname
// values (so this helper is asset-type agnostic).
func matchFilter(f *compiledFilter, dn, sam, hostname, name string) (bool, hitReason) {
	if f == nil {
		return false, hitReason{}
	}
	ndn := normaliseDN(dn)
	if _, ok := f.dns[ndn]; ok {
		return true, hitReason{Field: "dn", Pattern: dn}
	}
	for _, ou := range f.underOUs {
		if dnUnder(ndn, ou) {
			return true, hitReason{Field: "under_ou", Pattern: ou}
		}
	}
	for i, rx := range f.samPatterns {
		if sam != "" && rx.MatchString(sam) {
			return true, hitReason{Field: "sam", Pattern: f.samPatternsRaw[i]}
		}
	}
	for i, rx := range f.hostnamePatterns {
		if hostname != "" && rx.MatchString(hostname) {
			return true, hitReason{Field: "hostname", Pattern: f.hostnamePatternsRaw[i]}
		}
		// fallback on sAMAccountName without trailing $ for computers
		if sam != "" {
			if rx.MatchString(strings.TrimSuffix(sam, "$")) {
				return true, hitReason{Field: "hostname", Pattern: f.hostnamePatternsRaw[i]}
			}
		}
	}
	for i, rx := range f.namePatterns {
		if name != "" && rx.MatchString(name) {
			return true, hitReason{Field: "name", Pattern: f.namePatternsRaw[i]}
		}
	}
	for i, rx := range f.regex {
		if rx.MatchString(dn) {
			return true, hitReason{Field: "regex", Pattern: f.regexRaw[i]}
		}
	}
	return false, hitReason{}
}

// dnUnder reports whether dn is equal to parent or sits under the parent
// sub-tree. Both arguments must already be normalised.
func dnUnder(dn, parent string) bool {
	if dn == parent {
		return true
	}
	return strings.HasSuffix(dn, ","+parent)
}

// Per-asset accessors. Kept here so matcher.go owns all asset-to-rule wiring.

func userSam(u types.User) string   { return u.SAMAccountName }
func groupSam(g types.Group) string { return g.SAMAccountName }
func groupName(g types.Group) string {
	if g.CN != "" {
		return g.CN
	}
	return g.SAMAccountName
}
func computerSam(c types.Computer) string      { return c.SAMAccountName }
func computerHostname(c types.Computer) string { return c.DNSHostName }
func ouName(o types.OU) string                 { return o.Name }
