package saas

import "testing"

// TestSaaSURL_RejectsPlaintextHTTP — A_004 K8. `--saas-url` / ETCSEC_SAAS_URL used to be
// checked for non-emptiness only, so a cleartext enrolment put the bearer token and every
// later command on the wire in plaintext — and made T_017's download-host pinning
// decorative, since the pinned host is the one an on-path attacker impersonates.
func TestSaaSURL_RejectsPlaintextHTTP(t *testing.T) {
	tests := []struct {
		name          string
		url           string
		allowInsecure bool
		wantOK        bool
	}{
		{"documented production URL", "https://api.etcsec.com", false, true},
		{"https with port and path", "https://saas.corp.local:8443/api", false, true},
		{"https uppercase scheme", "HTTPS://api.etcsec.com", false, true},

		{"plaintext http refused by default", "http://api.etcsec.com", false, false},
		{"plaintext http on loopback still refused by default", "http://127.0.0.1:3000", false, false},
		{"no scheme", "api.etcsec.com", false, false},
		{"protocol-relative", "//api.etcsec.com", false, false},
		{"empty", "", false, false},
		{"whitespace only", "   ", false, false},
		{"https with no host", "https://", false, false},

		// The override is explicit and opt-in — and only relaxes http, nothing else.
		{"http accepted with explicit override", "http://127.0.0.1:3000", true, true},
		{"http accepted with override, remote host too", "http://api.etcsec.com", true, true},
		{"override does NOT unlock ftp", "ftp://api.etcsec.com", true, false},
		{"override does NOT unlock file", "file:///tmp/x", true, false},
		{"override does NOT unlock a missing scheme", "api.etcsec.com", true, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateSaaSURL(tc.url, tc.allowInsecure)
			if tc.wantOK && err != nil {
				t.Fatalf("ValidateSaaSURL(%q, %v) should be accepted, got: %v", tc.url, tc.allowInsecure, err)
			}
			if !tc.wantOK && err == nil {
				t.Fatalf("ValidateSaaSURL(%q, %v) must be REJECTED, but it was accepted", tc.url, tc.allowInsecure)
			}
		})
	}
}

// IsPlaintextSaaSURL drives the CLI warning printed when the override is used.
func TestIsPlaintextSaaSURL(t *testing.T) {
	plaintext := []string{"http://127.0.0.1:3000", "HTTP://api.etcsec.com", "  http://x  "}
	for _, u := range plaintext {
		if !IsPlaintextSaaSURL(u) {
			t.Errorf("IsPlaintextSaaSURL(%q) = false, want true", u)
		}
	}
	for _, u := range []string{"https://api.etcsec.com", "", "api.etcsec.com"} {
		if IsPlaintextSaaSURL(u) {
			t.Errorf("IsPlaintextSaaSURL(%q) = true, want false", u)
		}
	}
}
