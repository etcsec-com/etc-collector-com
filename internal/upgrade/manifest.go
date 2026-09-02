package upgrade

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"runtime"
	"strings"
	"time"
)

// DefaultManifestURL is the canonical source for the public collector release
// manifest. Hosted by ETCSec — same infra that serves the binary downloads.
//
// Format:
//
//	{
//	  "latest": "3.1.15",
//	  "versions": {
//	    "3.1.15": {
//	      "released": "2026-04-27T18:00:00Z",
//	      "artifacts": [
//	        { "os": "linux",   "arch": "amd64", "url": "...", "sha256": "..." },
//	        { "os": "windows", "arch": "amd64", "url": "...", "sha256": "..." },
//	        ...
//	      ]
//	    },
//	    ...
//	  }
//	}
//
// If the manifest URL ever moves, override via --download-url on the CLI.
const DefaultManifestURL = "https://get.etcsec.com/downloads/manifest.json"

// Artifact describes one downloadable file in the manifest.
type Artifact struct {
	OS     string `json:"os"`
	Arch   string `json:"arch"`
	URL    string `json:"url"`
	SHA256 string `json:"sha256"` // hex, no "sha256:" prefix
}

// VersionEntry is one release in the manifest.
type VersionEntry struct {
	Released  string     `json:"released"`
	Artifacts []Artifact `json:"artifacts"`
}

// Manifest is the parsed root document.
type Manifest struct {
	Latest   string                  `json:"latest"`
	Versions map[string]VersionEntry `json:"versions"`
}

// FetchManifest downloads the manifest JSON. Short timeout — this is a fast
// metadata fetch, not a binary download.
func FetchManifest(ctx context.Context, url string) (*Manifest, error) {
	if url == "" {
		url = DefaultManifestURL
	}
	cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(cctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, newErr(CodeNetworkUnreachable, "build manifest request failed", "Re-run the upgrade.", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, newErr(CodeNetworkUnreachable,
			"manifest unreachable: "+url,
			"Check network/proxy. Test: curl -I "+url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, newErr(CodeNetworkUnreachable,
			fmt.Sprintf("manifest HTTP %d", resp.StatusCode),
			"Verify the manifest URL or pass --download-url with an explicit binary URL.", nil)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1 MB cap
	if err != nil {
		return nil, newErr(CodeNetworkUnreachable, "read manifest body failed", "Re-run the upgrade.", err)
	}

	var m Manifest
	if err := json.Unmarshal(body, &m); err != nil {
		return nil, newErr(CodeInternal, "manifest JSON invalid", "Open a support ticket — server-side issue.", err)
	}
	return &m, nil
}

// ResolveVersion returns the requested version (or "latest" → m.Latest) and
// the matching Artifact for the running OS/arch. Both lookups produce
// CodeVersionNotFound when missing, with an actionable list of choices.
func (m *Manifest) ResolveVersion(requested string) (string, *Artifact, error) {
	version := requested
	if version == "" || strings.EqualFold(version, "latest") {
		version = m.Latest
	}
	if version == "" {
		return "", nil, newErr(CodeVersionNotFound,
			"manifest declares no 'latest' version",
			"Pass --version <X.Y.Z> explicitly or contact support.", nil)
	}

	entry, ok := m.Versions[version]
	if !ok {
		return version, nil, newErr(CodeVersionNotFound,
			"version "+version+" not in manifest",
			"Available versions: "+strings.Join(m.AvailableVersions(), ", "), nil)
	}

	for i := range entry.Artifacts {
		a := &entry.Artifacts[i]
		if a.OS == runtime.GOOS && a.Arch == runtime.GOARCH {
			return version, a, nil
		}
	}
	return version, nil, newErr(CodeVersionNotFound,
		fmt.Sprintf("version %s has no artifact for %s/%s", version, runtime.GOOS, runtime.GOARCH),
		"This platform is not supported for that release. Try --version latest.", nil)
}

// AvailableVersions returns all known versions, latest first by best-effort
// string sort (semver-aware sorting is overkill here — versions are short).
func (m *Manifest) AvailableVersions() []string {
	out := make([]string, 0, len(m.Versions))
	for v := range m.Versions {
		out = append(out, v)
	}
	// Crude descending sort: 3.1.15 > 3.1.14 > 3.1.10 > 3.1.9.
	// For the public CLI's UX (printing a list), this is good enough.
	for i := 0; i < len(out); i++ {
		for j := i + 1; j < len(out); j++ {
			if compareSemver(out[j], out[i]) > 0 {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}

// compareSemver returns -1/0/1. Strict numeric comparison of dot-separated
// segments. Non-numeric segments are compared lexically as a fallback.
func compareSemver(a, b string) int {
	as := strings.Split(a, ".")
	bs := strings.Split(b, ".")
	n := len(as)
	if len(bs) > n {
		n = len(bs)
	}
	for i := 0; i < n; i++ {
		var ai, bi int
		if i < len(as) {
			fmt.Sscanf(as[i], "%d", &ai)
		}
		if i < len(bs) {
			fmt.Sscanf(bs[i], "%d", &bi)
		}
		switch {
		case ai < bi:
			return -1
		case ai > bi:
			return 1
		}
	}
	return 0
}
