package discovery

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/providers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// stubLDAP is a minimal LDAPLike for tests.
type stubLDAP struct {
	users     []types.User
	groups    []types.Group
	computers []types.Computer
	ous       []types.OU
	domain    *types.DomainInfo
}

func (s *stubLDAP) GetUsers(_ context.Context, _ providers.QueryOptions) ([]types.User, error) {
	return s.users, nil
}
func (s *stubLDAP) GetGroups(_ context.Context, _ providers.QueryOptions) ([]types.Group, error) {
	return s.groups, nil
}
func (s *stubLDAP) GetComputers(_ context.Context, _ providers.QueryOptions) ([]types.Computer, error) {
	return s.computers, nil
}
func (s *stubLDAP) GetOUs(_ context.Context, _ providers.QueryOptions) ([]types.OU, error) {
	return s.ous, nil
}
func (s *stubLDAP) GetDomainInfo(_ context.Context) (*types.DomainInfo, error) {
	return s.domain, nil
}

func TestRun_DefaultSampleSize(t *testing.T) {
	stub := &stubLDAP{
		users: make([]types.User, 100),
	}
	for i := range stub.users {
		stub.users[i].DN = "CN=u" + itoa(i) + ",DC=x"
	}
	m, err := Run(context.Background(), stub, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if m.Counts.Users != 100 {
		t.Errorf("Counts.Users = %d, want 100", m.Counts.Users)
	}
	if len(m.Samples.Users) != 50 {
		t.Errorf("default SampleSize should cap to 50, got %d", len(m.Samples.Users))
	}
}

func TestRun_FullListing(t *testing.T) {
	stub := &stubLDAP{
		users:     make([]types.User, 1200),
		computers: make([]types.Computer, 300),
		groups:    make([]types.Group, 80),
		ous:       make([]types.OU, 42),
	}
	for i := range stub.users {
		stub.users[i].DN = "CN=u" + itoa(i) + ",OU=Users,DC=x"
		stub.users[i].SAMAccountName = "u" + itoa(i)
	}
	for i := range stub.computers {
		stub.computers[i].DN = "CN=PC" + itoa(i) + ",OU=Computers,DC=x"
	}
	for i := range stub.groups {
		stub.groups[i].DN = "CN=g" + itoa(i) + ",OU=Groups,DC=x"
	}
	for i := range stub.ous {
		stub.ous[i].DN = "OU=o" + itoa(i) + ",DC=x"
	}

	m, err := Run(context.Background(), stub, Options{FullListing: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Samples.Users) != m.Counts.Users {
		t.Errorf("full-listing users: have %d samples for %d count", len(m.Samples.Users), m.Counts.Users)
	}
	if len(m.Samples.Computers) != m.Counts.Computers {
		t.Errorf("full-listing computers: have %d samples for %d count", len(m.Samples.Computers), m.Counts.Computers)
	}
	if len(m.Samples.Groups) != m.Counts.Groups {
		t.Errorf("full-listing groups: have %d samples for %d count", len(m.Samples.Groups), m.Counts.Groups)
	}
	if len(m.Samples.OUs) != m.Counts.OUs {
		t.Errorf("full-listing ous: have %d samples for %d count", len(m.Samples.OUs), m.Counts.OUs)
	}
}

func TestRun_ParentOuDN(t *testing.T) {
	stub := &stubLDAP{
		users: []types.User{
			{DN: "CN=krbtgt,CN=Users,DC=x,DC=y", SAMAccountName: "krbtgt"},
			{DN: "CN=Alice,OU=Employees,DC=x,DC=y", SAMAccountName: "alice"},
		},
		computers: []types.Computer{
			{DN: "CN=PC1,OU=Workstations,OU=IT,DC=x,DC=y"},
		},
		groups: []types.Group{
			{DN: "CN=Admins,CN=Users,DC=x,DC=y"},
		},
		ous: []types.OU{
			{DN: "OU=Employees,DC=x,DC=y"},
		},
	}
	m, err := Run(context.Background(), stub, Options{FullListing: true})
	if err != nil {
		t.Fatal(err)
	}
	// krbtgt is under CN=Users, not under a real OU, but parentOuDN still reflects the raw parent.
	if m.Samples.Users[0].ParentOuDN != "CN=Users,DC=x,DC=y" {
		t.Errorf("krbtgt parentOuDN = %q, want CN=Users,DC=x,DC=y", m.Samples.Users[0].ParentOuDN)
	}
	if m.Samples.Users[1].ParentOuDN != "OU=Employees,DC=x,DC=y" {
		t.Errorf("alice parentOuDN = %q", m.Samples.Users[1].ParentOuDN)
	}
	if m.Samples.Computers[0].ParentOuDN != "OU=Workstations,OU=IT,DC=x,DC=y" {
		t.Errorf("PC1 parentOuDN = %q", m.Samples.Computers[0].ParentOuDN)
	}
	if m.Samples.OUs[0].ParentOuDN != "DC=x,DC=y" {
		t.Errorf("OU=Employees parentOuDN = %q", m.Samples.OUs[0].ParentOuDN)
	}
}

func TestRun_GroupMembers_IncludedWithFullListing(t *testing.T) {
	stub := &stubLDAP{
		groups: []types.Group{
			{DN: "CN=Admins,CN=Users,DC=x", Members: []string{"CN=alice,DC=x", "CN=bob,DC=x"}},
			{DN: "CN=EmptyGroup,CN=Users,DC=x", Members: nil},
		},
	}
	m, err := Run(context.Background(), stub, Options{FullListing: true})
	if err != nil {
		t.Fatal(err)
	}
	if m.Samples.Groups[0].Members == nil {
		t.Fatal("Admins: Members should be non-nil with FullListing")
	}
	got := *m.Samples.Groups[0].Members
	if len(got) != 2 || got[0] != "CN=alice,DC=x" || got[1] != "CN=bob,DC=x" {
		t.Errorf("Admins: Members = %v, want [alice, bob]", got)
	}
	// Empty group: non-nil pointer to empty slice so JSON emits "members":[].
	if m.Samples.Groups[1].Members == nil {
		t.Fatal("EmptyGroup: Members should be non-nil (empty slice), not nil")
	}
	if len(*m.Samples.Groups[1].Members) != 0 {
		t.Errorf("EmptyGroup: Members len = %d, want 0", len(*m.Samples.Groups[1].Members))
	}
}

func TestRun_GroupMembers_OmittedByDefault(t *testing.T) {
	stub := &stubLDAP{
		groups: []types.Group{
			{DN: "CN=Admins,CN=Users,DC=x", Members: []string{"CN=alice,DC=x"}},
		},
	}
	m, err := Run(context.Background(), stub, Options{}) // default (no FullListing)
	if err != nil {
		t.Fatal(err)
	}
	if m.Samples.Groups[0].Members != nil {
		t.Errorf("default mode: Members should be nil (omitted from JSON), got %v", *m.Samples.Groups[0].Members)
	}
}

func TestRun_GroupMembers_ExplicitOptInWithoutFullListing(t *testing.T) {
	stub := &stubLDAP{
		groups: []types.Group{
			{DN: "CN=Admins,CN=Users,DC=x", Members: []string{"CN=alice,DC=x"}},
		},
	}
	tru := true
	m, err := Run(context.Background(), stub, Options{IncludeGroupMembers: &tru})
	if err != nil {
		t.Fatal(err)
	}
	if m.Samples.Groups[0].Members == nil {
		t.Error("explicit opt-in without FullListing: Members should be non-nil")
	}
}

func TestRun_GroupMembers_ExplicitOptOut(t *testing.T) {
	stub := &stubLDAP{
		groups: []types.Group{
			{DN: "CN=Admins,CN=Users,DC=x", Members: []string{"CN=alice,DC=x"}},
		},
	}
	f := false
	m, err := Run(context.Background(), stub, Options{FullListing: true, IncludeGroupMembers: &f})
	if err != nil {
		t.Fatal(err)
	}
	if m.Samples.Groups[0].Members != nil {
		t.Errorf("explicit opt-out with FullListing=true: Members should be nil")
	}
}

func TestRun_ProgressCallback(t *testing.T) {
	stub := &stubLDAP{users: make([]types.User, 3)}
	for i := range stub.users {
		stub.users[i].DN = "CN=u" + itoa(i) + ",DC=x"
	}
	var phases []string
	_, err := Run(context.Background(), stub, Options{
		Progress: func(evt ProgressEvent) { phases = append(phases, evt.Phase) },
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"fetching_users", "users_done", "groups_done", "computers_done", "ous_done", "done"}
	if len(phases) != len(want) {
		t.Fatalf("phases = %v, want %v", phases, want)
	}
	for i, p := range want {
		if phases[i] != p {
			t.Errorf("phase[%d] = %q, want %q", i, phases[i], p)
		}
	}
}

// itoa without importing strconv (keeps the test file small).
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := false
	if n < 0 {
		neg = true
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
