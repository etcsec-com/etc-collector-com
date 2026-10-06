package exclusions

import (
	"strings"
	"testing"

	"github.com/etcsec-com/etc-collector/pkg/types"
)

func TestNormaliseDN(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"CN=Foo,OU=Bar,DC=acme,DC=corp", "cn=foo,ou=bar,dc=acme,dc=corp"},
		{"  CN=Foo , OU = Bar ", "cn=foo,ou=bar"},
		{"CN = Foo,DC=x", "cn=foo,dc=x"},
		{"", ""},
	}
	for _, c := range cases {
		got := normaliseDN(c.in)
		if got != c.want {
			t.Errorf("normaliseDN(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestGlobToRegex(t *testing.T) {
	cases := []struct {
		pattern string
		match   []string
		noMatch []string
	}{
		{"svc-*", []string{"svc-sql", "SVC-BACKUP"}, []string{"sql-svc", "admin"}},
		{"*-legacy", []string{"app-legacy", "CRM-LEGACY"}, []string{"legacy-app", "svc"}},
		{"*temp*", []string{"tempuser", "ad-temp-01"}, []string{"permanent"}},
		{"XP-?", []string{"XP-1", "xp-a"}, []string{"XP-", "XP-12"}},
	}
	for _, c := range cases {
		rx, err := globToRegex(c.pattern)
		if err != nil {
			t.Fatalf("globToRegex(%q): %v", c.pattern, err)
		}
		for _, s := range c.match {
			if !rx.MatchString(s) {
				t.Errorf("pattern %q did not match %q", c.pattern, s)
			}
		}
		for _, s := range c.noMatch {
			if rx.MatchString(s) {
				t.Errorf("pattern %q should not match %q", c.pattern, s)
			}
		}
	}
}

func TestDnUnder(t *testing.T) {
	if !dnUnder("cn=foo,ou=bar,dc=x", "ou=bar,dc=x") {
		t.Error("expected cn=foo to be under ou=bar")
	}
	if !dnUnder("ou=bar,dc=x", "ou=bar,dc=x") {
		t.Error("equal DN should count as under")
	}
	if dnUnder("cn=foo,ou=other,dc=x", "ou=bar,dc=x") {
		t.Error("different branch should not be under")
	}
	if dnUnder("ou=barstuff,dc=x", "ou=bar,dc=x") {
		t.Error("prefix-suffix collision should not match")
	}
}

func TestLoadFromBytesVersionAndHash(t *testing.T) {
	y := []byte(`
version: 1
users:
  exclude:
    sam_patterns: ["svc-*"]
`)
	cfg, err := LoadFromBytes(y)
	if err != nil {
		t.Fatalf("LoadFromBytes: %v", err)
	}
	if cfg.Hash == "" || len(cfg.Hash) != 64 {
		t.Errorf("expected 64-char hex hash, got %q", cfg.Hash)
	}
	// Loading the same content twice yields the same hash.
	cfg2, _ := LoadFromBytes(y)
	if cfg.Hash != cfg2.Hash {
		t.Errorf("hash not deterministic: %q vs %q", cfg.Hash, cfg2.Hash)
	}
}

func TestLoadRejectsInvalidRegex(t *testing.T) {
	y := []byte(`
version: 1
users:
  exclude:
    regex: ["[not-a-valid-regex"]
`)
	_, err := LoadFromBytes(y)
	if err == nil || !strings.Contains(err.Error(), "regex") {
		t.Errorf("expected regex validation error, got: %v", err)
	}
}

func TestLoadRejectsUnknownVersion(t *testing.T) {
	y := []byte(`version: 99`)
	_, err := LoadFromBytes(y)
	if err == nil || !strings.Contains(err.Error(), "version") {
		t.Errorf("expected version error, got: %v", err)
	}
}

// --- ApplyToData integration tests ---

// stubData is a minimal DataLike for tests.
type stubData struct {
	users     []types.User
	computers []types.Computer
	groups    []types.Group
	ous       []types.OU
}

func (s *stubData) GetUsers() []types.User          { return s.users }
func (s *stubData) SetUsers(u []types.User)         { s.users = u }
func (s *stubData) GetGroups() []types.Group        { return s.groups }
func (s *stubData) SetGroups(g []types.Group)       { s.groups = g }
func (s *stubData) GetComputers() []types.Computer  { return s.computers }
func (s *stubData) SetComputers(c []types.Computer) { s.computers = c }
func (s *stubData) GetOUs() []types.OU              { return s.ous }
func (s *stubData) SetOUs(o []types.OU)             { s.ous = o }

func TestApplyToData_GlobSAM(t *testing.T) {
	cfg, err := LoadFromBytes([]byte(`
version: 1
users:
  exclude:
    sam_patterns: ["svc-*"]
`))
	if err != nil {
		t.Fatal(err)
	}
	data := &stubData{users: []types.User{
		{DN: "CN=Alice,DC=x", SAMAccountName: "alice"},
		{DN: "CN=Svc,DC=x", SAMAccountName: "svc-sql"},
		{DN: "CN=Bob,DC=x", SAMAccountName: "SVC-BACKUP"},
	}}
	report := ApplyToData(data, cfg)
	if len(data.users) != 1 || data.users[0].SAMAccountName != "alice" {
		t.Errorf("expected alice only, got %+v", data.users)
	}
	counts := report.AssetCounts["users"]
	if counts.Total != 3 || counts.Scanned != 1 || counts.Excluded != 2 {
		t.Errorf("counts wrong: %+v", counts)
	}
	if len(counts.Reasons) != 1 || counts.Reasons[0].Matched != 2 {
		t.Errorf("expected 1 reason matching 2 objects, got %+v", counts.Reasons)
	}
}

func TestApplyToData_UnderOU(t *testing.T) {
	cfg, _ := LoadFromBytes([]byte(`
version: 1
computers:
  exclude:
    under_ous: ["OU=Legacy,DC=acme,DC=corp"]
`))
	data := &stubData{computers: []types.Computer{
		{DN: "CN=SRV-01,OU=Prod,DC=acme,DC=corp"},
		{DN: "CN=SRV-OLD,OU=Legacy,DC=acme,DC=corp"},
		{DN: "CN=XP-1,OU=Sub,OU=Legacy,DC=acme,DC=corp"},
	}}
	ApplyToData(data, cfg)
	if len(data.computers) != 1 || !strings.Contains(data.computers[0].DN, "SRV-01") {
		t.Errorf("expected only SRV-01 kept, got %+v", data.computers)
	}
}

func TestApplyToData_DNNormalization(t *testing.T) {
	cfg, _ := LoadFromBytes([]byte(`
version: 1
users:
  exclude:
    dns: ["CN = Guest , CN = Users , DC = X "]
`))
	data := &stubData{users: []types.User{
		{DN: "cn=guest,cn=users,dc=x", SAMAccountName: "guest"},
		{DN: "CN=Alice,DC=x", SAMAccountName: "alice"},
	}}
	ApplyToData(data, cfg)
	if len(data.users) != 1 || data.users[0].SAMAccountName != "alice" {
		t.Errorf("expected only alice kept, got %+v", data.users)
	}
}

func TestApplyToData_Empty(t *testing.T) {
	data := &stubData{users: []types.User{{DN: "CN=A"}, {DN: "CN=B"}}}
	report := ApplyToData(data, nil)
	if len(data.users) != 2 {
		t.Error("nil config should be passthrough")
	}
	if report == nil {
		t.Error("report should not be nil even for nil config")
	}
}

func TestApplyPerDetector(t *testing.T) {
	cfg, err := LoadFromBytes([]byte(`
version: 1
detectors:
  - id: LAPS_NOT_DEPLOYED
    reason: "Tenable PAM"
    scope:
      computers:
        under_ous: ["OU=Tenable,DC=x"]
`))
	if err != nil {
		t.Fatal(err)
	}
	data := &stubData{computers: []types.Computer{
		{DN: "CN=PC1,OU=Prod,DC=x"},
		{DN: "CN=PC2,OU=Tenable,DC=x"},
		{DN: "CN=PC3,OU=Tenable,DC=x"},
	}}
	_, computers, _, _, excl := ApplyPerDetector(cfg, "LAPS_NOT_DEPLOYED", data)
	if len(computers) != 1 || !strings.Contains(computers[0].DN, "PC1") {
		t.Errorf("expected PC1 only, got %+v", computers)
	}
	if len(excl) != 1 || excl[0].Matched != 2 || excl[0].DetectorID != "LAPS_NOT_DEPLOYED" {
		t.Errorf("unexpected detector exclusion: %+v", excl)
	}
	// Another detector is untouched
	_, computers2, _, _, excl2 := ApplyPerDetector(cfg, "OTHER_DETECTOR", data)
	if len(computers2) != 3 || len(excl2) != 0 {
		t.Errorf("other detector should see all 3 computers, got %d (excl=%+v)", len(computers2), excl2)
	}
}

func TestFilterDNs(t *testing.T) {
	cfg, _ := LoadFromBytes([]byte(`
version: 1
computers:
  exclude:
    under_ous: ["OU=Legacy,DC=x"]
`))
	dns := []string{
		"CN=A,OU=Prod,DC=x",
		"CN=B,OU=Legacy,DC=x",
		"CN=C,OU=Prod,DC=x",
	}
	out := FilterDNs(cfg, dns, "computers")
	if len(out) != 2 {
		t.Errorf("expected 2 DNs, got %d: %+v", len(out), out)
	}
}

func TestIsEmpty(t *testing.T) {
	var nilCfg *Config
	if !nilCfg.IsEmpty() {
		t.Error("nil config should be empty")
	}
	empty := &Config{Version: 1}
	if !empty.IsEmpty() {
		t.Error("bare config should be empty")
	}
	cfg, _ := LoadFromBytes([]byte(`version: 1
users:
  exclude:
    sam_patterns: ["*"]`))
	if cfg.IsEmpty() {
		t.Error("config with rules should not be empty")
	}
}
