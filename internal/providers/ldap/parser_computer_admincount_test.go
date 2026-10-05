package ldap

import (
	"testing"

	"github.com/go-ldap/ldap/v3"
)

// TestParseComputer_AdminCount covers COMPUTER_ADMIN_COUNT:
// types.Computer.AdminCount was never assigned by parseComputer, and
// "adminCount" was never requested in computerAttributes - so the AD side
// of ADMIN_COUNT_ORPHANED_ON_COMPUTER-style detectors stayed permanently
// false regardless of the real attribute. parseUser/parseGroup already
// populate the same field the same way; parseComputer never did.
func TestParseComputer_AdminCount(t *testing.T) {
	entry := ldap.NewEntry("CN=WKS01,OU=Computers,DC=contoso,DC=com", map[string][]string{
		"sAMAccountName": {"WKS01$"},
		"adminCount":     {"1"},
	})

	c := parseComputer(entry)

	if !c.AdminCount {
		t.Fatalf("expected AdminCount=true for a computer with adminCount=1, got false")
	}
}

// TestParseComputer_AdminCount_AbsentAttribute guards against
// over-eagerness: a computer with no adminCount attribute at all must not
// be flagged.
func TestParseComputer_AdminCount_AbsentAttribute(t *testing.T) {
	entry := ldap.NewEntry("CN=WKS02,OU=Computers,DC=contoso,DC=com", map[string][]string{
		"sAMAccountName": {"WKS02$"},
	})

	c := parseComputer(entry)

	if c.AdminCount {
		t.Fatalf("expected AdminCount=false when adminCount is absent, got true")
	}
}
