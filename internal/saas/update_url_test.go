package saas

import (
	"strings"
	"testing"
)

// enrolledURL is what a real collector has in credentials.json after enrollment:
// the SaaS API origin, which is also the host the cloud builds downloadUrl from
// (collectors.ts: `${SAAS_API_URL}/api/fleet/download/...`).
const enrolledURL = "https://api.etcsec.com"

// legitDownloadURL mirrors the URL the cloud actually issues, query string included.
const legitDownloadURL = "https://api.etcsec.com/api/fleet/download/etc-collector-3.2.0-linux-amd64.zip?sig=deadbeef&exp=1753731600&cid=11111111-2222-3333-4444-555555555555"

func updateCmdParams(downloadURL string) map[string]interface{} {
	return map[string]interface{}{
		"targetVersion": "3.2.0",
		"downloadUrl":   downloadURL,
		"checksum":      "sha256:" + strings.Repeat("ab", 32),
	}
}

// TestUpdateURL_RejectsForeignHost — A_004 K1. The checksum arrives in the same
// command payload as the URL, so it proves nothing about the artifact's origin;
// the enrolled host is the only trust anchor. Host equality is on the PARSED host,
// which is why the userinfo and suffix tricks below are caught.
func TestUpdateURL_RejectsForeignHost(t *testing.T) {
	tests := []struct {
		name       string
		enrolled   string
		downloadTo string
		wantOK     bool
	}{
		{"legitimate signed URL from enrolled host", enrolledURL, legitDownloadURL, true},
		{"explicit default port matches implicit", enrolledURL, "https://api.etcsec.com:443/api/fleet/download/x.zip", true},
		{"host comparison is case-insensitive", enrolledURL, "https://API.Etcsec.COM/api/fleet/download/x.zip", true},
		{"enrolled URL with trailing slash", "https://api.etcsec.com/", legitDownloadURL, true},
		{"self-hosted enrolled origin with port", "https://saas.corp.local:8443", "https://saas.corp.local:8443/api/fleet/download/x.zip", true},

		{"foreign host", enrolledURL, "https://evil.example/x.zip", false},
		{"suffix trick", enrolledURL, "https://api.etcsec.com.evil.example/x.zip", false},
		{"prefix trick in path", enrolledURL, "https://evil.example/api.etcsec.com/x.zip", false},
		{"userinfo trick (a string prefix check would accept this)", enrolledURL, "https://api.etcsec.com@evil.example/x.zip", false},
		{"same host, different port", enrolledURL, "https://api.etcsec.com:8443/x.zip", false},
		{"subdomain of enrolled host", enrolledURL, "https://cdn.api.etcsec.com/x.zip", false},
		{"hardcoded CDN name is NOT an implicit allowlist", enrolledURL, "https://get.etcsec.com/x.zip", false},
		{"no host at all", enrolledURL, "https:///x.zip", false},
		{"not enrolled — fail closed", "", legitDownloadURL, false},
		{"unparseable enrolled URL — fail closed", "://nope", legitDownloadURL, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseUpdateParams(updateCmdParams(tc.downloadTo), tc.enrolled)
			if tc.wantOK {
				if err != nil {
					t.Fatalf("expected downloadUrl %q to be accepted for enrolled %q, got error: %v",
						tc.downloadTo, tc.enrolled, err)
				}
				if got.downloadURL != tc.downloadTo {
					t.Errorf("downloadURL = %q, want %q", got.downloadURL, tc.downloadTo)
				}
				if got.allowedHost == "" {
					t.Error("allowedHost must be set so redirects stay pinned")
				}
				return
			}
			if err == nil {
				t.Fatalf("expected downloadUrl %q to be REJECTED for enrolled %q, but it was accepted",
					tc.downloadTo, tc.enrolled)
			}
		})
	}
}

// TestUpdateURL_RejectsNonHTTPS keeps the pre-existing property: plaintext or
// non-HTTP(S) schemes are refused even when the host itself is the enrolled one.
func TestUpdateURL_RejectsNonHTTPS(t *testing.T) {
	rejected := []string{
		"http://api.etcsec.com/api/fleet/download/x.zip",
		"ftp://api.etcsec.com/x.zip",
		"file:///tmp/x.zip",
		"//api.etcsec.com/x.zip",
		"api.etcsec.com/x.zip",
		"/api/fleet/download/x.zip",
	}
	for _, downloadURL := range rejected {
		t.Run(downloadURL, func(t *testing.T) {
			if _, err := parseUpdateParams(updateCmdParams(downloadURL), enrolledURL); err == nil {
				t.Fatalf("expected non-HTTPS downloadUrl %q to be rejected", downloadURL)
			}
		})
	}

	// url.Parse lowercases the scheme, so an uppercased HTTPS URL is still HTTPS.
	if _, err := parseUpdateParams(updateCmdParams("HTTPS://api.etcsec.com/x.zip"), enrolledURL); err != nil {
		t.Errorf("uppercase HTTPS scheme should be accepted: %v", err)
	}
}
