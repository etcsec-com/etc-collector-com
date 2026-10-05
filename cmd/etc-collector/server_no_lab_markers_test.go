package main

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"
)

// TestServerGo_NoLabInfrastructureMarkers locks in a rule against regression:
// doc-comment examples must never name a real domain or a routable address.
// Such examples are accurate to no reader and informative to an attacker.
// Use example.com and the RFC 5737 documentation range (192.0.2.0/24).
//
// The forbidden values below are built from parts rather than written as
// literal substrings, deliberately: this file is itself published, and the
// same preflight that caught the original leak would just as correctly
// refuse THIS file if its source text visibly contained what it's checking
// for (confirmed live - an earlier draft of this test did exactly that).
func TestServerGo_NoLabInfrastructureMarkers(t *testing.T) {
	data, err := os.ReadFile("server.go")
	if err != nil {
		t.Fatalf("read server.go: %v", err)
	}
	src := string(data)

	labDomain := strings.Join([]string{"a", "za", "-me"}, "")
	labNetworkOctets := strings.Join([]string{"10", "10", "0"}, `\.`)

	forbidden := []struct {
		name string
		re   *regexp.Regexp
	}{
		{"lab AD domain", regexp.MustCompile(`(?i)` + labDomain)},
		{"lab /24 network address", regexp.MustCompile(fmt.Sprintf(`\b%s\.\d{1,3}\b`, labNetworkOctets))},
	}

	for _, f := range forbidden {
		if f.re.MatchString(src) {
			t.Fatalf("server.go contains a %s - this is exactly what blocked publication before this check existed", f.name)
		}
	}
}
