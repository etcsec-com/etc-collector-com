// Package exclusions implements asset-level and detector-level filtering for
// audit runs. Auditors can exclude specific users/computers/groups/OUs from an
// audit (by DN, subtree, glob pattern on sAMAccountName/hostname, or regex),
// and can disable individual detectors on scoped asset subsets.
//
// Exclusions are applied in the engine after data collection, before detectors
// run. The resulting AuditResult embeds the rulesHash + coverage counts so the
// filter trail is auditable.
package exclusions

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config is the top-level exclusion configuration. Either loaded from a YAML
// file (CLI) or unmarshalled from a SaaS push payload.
type Config struct {
	Version   int            `yaml:"version" json:"version"`
	Hash      string         `yaml:"hash,omitempty" json:"hash,omitempty"` // filled by Load; echoed in audit result
	Users     *AssetRules    `yaml:"users,omitempty" json:"users,omitempty"`
	Computers *AssetRules    `yaml:"computers,omitempty" json:"computers,omitempty"`
	Groups    *AssetRules    `yaml:"groups,omitempty" json:"groups,omitempty"`
	OUs       *AssetRules    `yaml:"ous,omitempty" json:"ous,omitempty"`
	Detectors []DetectorRule `yaml:"detectors,omitempty" json:"detectors,omitempty"`

	// compiled holds precomputed matchers. Not serialised.
	compiled *compiledConfig `yaml:"-" json:"-"`
}

// AssetRules holds scope and filters for a specific asset type.
type AssetRules struct {
	// Scope limits the LDAP enumeration to these sub-trees (future v2 hook:
	// today applied post-query as an under_ous filter on include side).
	Scope []string `yaml:"scope,omitempty" json:"scope,omitempty"`

	// Include, if non-nil, keeps only objects matching at least one rule.
	Include *Filter `yaml:"include,omitempty" json:"include,omitempty"`

	// Exclude drops objects matching at least one rule. Applied after Include.
	Exclude *Filter `yaml:"exclude,omitempty" json:"exclude,omitempty"`
}

// Filter is a set of match rules. Any rule match marks the object as hit.
type Filter struct {
	DNs              []string `yaml:"dns,omitempty" json:"dns,omitempty"`                             // exact DN (normalised)
	UnderOUs         []string `yaml:"under_ous,omitempty" json:"under_ous,omitempty"`                 // subtree prefix
	SamPatterns      []string `yaml:"sam_patterns,omitempty" json:"sam_patterns,omitempty"`           // glob on sAMAccountName (users, groups)
	HostnamePatterns []string `yaml:"hostname_patterns,omitempty" json:"hostname_patterns,omitempty"` // glob on dNSHostName/sAM (computers)
	NamePatterns     []string `yaml:"name_patterns,omitempty" json:"name_patterns,omitempty"`         // glob on CN/name (groups, OUs)
	Regex            []string `yaml:"regex,omitempty" json:"regex,omitempty"`                         // regex on DN
}

// DetectorRule excludes the referenced detector from running against the
// matching asset subset. The asset itself remains scanned by every other
// detector.
type DetectorRule struct {
	ID     string             `yaml:"id" json:"id"`
	Reason string             `yaml:"reason,omitempty" json:"reason,omitempty"`
	Scope  map[string]*Filter `yaml:"scope,omitempty" json:"scope,omitempty"` // key: "users" | "computers" | "groups" | "ous"
}

// Load reads and validates an exclusions YAML file. Validation errors surface
// the offending field/path so the auditor can fix the config before rerunning.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("exclusions: read %s: %w", path, err)
	}
	return LoadFromBytes(raw)
}

// LoadFromBytes parses + validates an exclusions config from a YAML byte slice.
func LoadFromBytes(raw []byte) (*Config, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var cfg Config
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("exclusions: parse yaml: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if err := cfg.compile(); err != nil {
		return nil, err
	}
	cfg.Hash = cfg.computeHash()
	return &cfg, nil
}

// LoadFromMap accepts an unmarshalled SaaS command payload (map[string]interface{})
// and converts it to a validated Config. Uses YAML round-trip for consistency.
func LoadFromMap(raw map[string]interface{}) (*Config, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	b, err := yaml.Marshal(raw)
	if err != nil {
		return nil, fmt.Errorf("exclusions: re-marshal SaaS payload: %w", err)
	}
	return LoadFromBytes(b)
}

// Validate performs structural checks on the config before compilation.
func (c *Config) Validate() error {
	if c == nil {
		return nil
	}
	if c.Version == 0 {
		c.Version = 1 // default
	}
	if c.Version != 1 {
		return fmt.Errorf("exclusions: unsupported version %d (expected 1)", c.Version)
	}
	for name, rules := range map[string]*AssetRules{
		"users":     c.Users,
		"computers": c.Computers,
		"groups":    c.Groups,
		"ous":       c.OUs,
	} {
		if rules == nil {
			continue
		}
		if err := rules.validate(name); err != nil {
			return err
		}
	}
	for i, d := range c.Detectors {
		if strings.TrimSpace(d.ID) == "" {
			return fmt.Errorf("exclusions: detectors[%d].id is required", i)
		}
		for scope, f := range d.Scope {
			if !isValidScopeKey(scope) {
				return fmt.Errorf("exclusions: detectors[%d].scope[%s] unknown asset type (allowed: users, computers, groups, ous)", i, scope)
			}
			if f == nil {
				continue
			}
			if err := f.validate(fmt.Sprintf("detectors[%d].scope.%s", i, scope)); err != nil {
				return err
			}
		}
	}
	return nil
}

func (r *AssetRules) validate(name string) error {
	if r.Include != nil {
		if err := r.Include.validate(name + ".include"); err != nil {
			return err
		}
	}
	if r.Exclude != nil {
		if err := r.Exclude.validate(name + ".exclude"); err != nil {
			return err
		}
	}
	return nil
}

func (f *Filter) validate(path string) error {
	for i, rx := range f.Regex {
		if _, err := regexp.Compile(rx); err != nil {
			return fmt.Errorf("exclusions: %s.regex[%d] invalid: %w", path, i, err)
		}
	}
	for _, dn := range f.DNs {
		if strings.TrimSpace(dn) == "" {
			return fmt.Errorf("exclusions: %s.dns contains empty string", path)
		}
	}
	for _, dn := range f.UnderOUs {
		if strings.TrimSpace(dn) == "" {
			return fmt.Errorf("exclusions: %s.under_ous contains empty string", path)
		}
	}
	return nil
}

func isValidScopeKey(k string) bool {
	switch k {
	case "users", "computers", "groups", "ous":
		return true
	}
	return false
}

// computeHash returns a deterministic sha256 over the normalised JSON payload.
// Embedded in every audit result so external auditors can verify the config
// used for a given run.
func (c *Config) computeHash() string {
	snapshot := *c
	snapshot.Hash = "" // don't include the hash field in the hash input
	snapshot.compiled = nil
	b, err := json.Marshal(snapshot)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// IsEmpty reports whether the config has no effective rules (used to short-
// circuit ApplyToData early).
func (c *Config) IsEmpty() bool {
	if c == nil {
		return true
	}
	empty := func(r *AssetRules) bool {
		if r == nil {
			return true
		}
		return len(r.Scope) == 0 && r.Include.empty() && r.Exclude.empty()
	}
	if !empty(c.Users) || !empty(c.Computers) || !empty(c.Groups) || !empty(c.OUs) {
		return false
	}
	return len(c.Detectors) == 0
}

func (f *Filter) empty() bool {
	if f == nil {
		return true
	}
	return len(f.DNs) == 0 && len(f.UnderOUs) == 0 && len(f.SamPatterns) == 0 &&
		len(f.HostnamePatterns) == 0 && len(f.NamePatterns) == 0 && len(f.Regex) == 0
}
