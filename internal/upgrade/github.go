package upgrade

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"runtime"
	"strings"
	"time"
)

// githubBaseURL is "https://github.com" in production. Tests point it at an
// httptest server to exercise the redirect-chasing logic without touching
// the network - see github_test.go.
var githubBaseURL = "https://github.com"

// DefaultReleasesRepo is the public GitHub repository that CI builds and
// publishes releases to (.github/workflows/release.yml). It is the default
// upgrade source - a copy hosted elsewhere (get.etcsec.com) can
// drift from it, and did (manifest.json/latest.json 404 while the release
// itself was live).
//
// Reached ONLY through github.com's HTML redirects (releases/latest,
// releases/latest/download/<asset>), never api.github.com: the unauthenticated
// REST API is capped at 60 requests/hour/IP, and a fleet of collectors behind
// one NAT - an enterprise customer - would rate-limit itself, with a 403 that
// wouldn't look like its actual cause. The redirects carry no such limit.
const DefaultReleasesRepo = "etcsec-com/etc-collector-com"

// resolveLatestTag finds the tag the repo's "latest" release currently points
// to, by reading the Location header of the one redirect hop from
// /releases/latest - without following it, so this never downloads the HTML
// release page. HEAD is used for the same reason: metadata only.
func resolveLatestTag(ctx context.Context, client *http.Client, repo string) (string, error) {
	url := githubBaseURL + "/" + repo + "/releases/latest"
	cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(cctx, http.MethodHead, url, nil)
	if err != nil {
		return "", newErr(CodeNetworkUnreachable, "build latest-release request failed", "Re-run the upgrade.", err)
	}

	// Shallow-copy so we don't leave a permanent CheckRedirect override on a
	// client the caller may reuse for the actual (multi-redirect) downloads.
	c := *client
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	resp, err := c.Do(req)
	if err != nil {
		return "", newErr(CodeNetworkUnreachable,
			"github.com unreachable: "+url,
			"Check network/proxy. Test: curl -I "+url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound && resp.StatusCode != http.StatusMovedPermanently {
		return "", newErr(CodeNetworkUnreachable,
			fmt.Sprintf("expected a redirect from %s, got HTTP %d", url, resp.StatusCode),
			"github.com may be having an outage, or the repo/release moved. Pass --manifest-url or --download-url to bypass.", nil)
	}

	loc := resp.Header.Get("Location")
	tag := loc[strings.LastIndex(loc, "/")+1:]
	if tag == "" {
		return "", newErr(CodeVersionNotFound,
			"could not read release tag from redirect: "+loc,
			"Pass --version <X.Y.Z> explicitly.", nil)
	}
	return tag, nil
}

// releaseAssetName returns the filename release.yml publishes for the given
// version/OS/arch. Only the five combinations the workflow actually builds
// are supported.
func releaseAssetName(version, goos, goarch string) (string, error) {
	switch {
	case goos == "windows" && goarch == "amd64":
		return fmt.Sprintf("etc-collector-%s-windows-amd64.zip", version), nil
	case goos == "linux" && goarch == "amd64":
		return fmt.Sprintf("etc-collector-%s-linux-amd64.tar.gz", version), nil
	case goos == "linux" && goarch == "arm64":
		return fmt.Sprintf("etc-collector-%s-linux-arm64.tar.gz", version), nil
	case goos == "darwin" && goarch == "amd64":
		return fmt.Sprintf("etc-collector-%s-darwin-amd64.tar.gz", version), nil
	case goos == "darwin" && goarch == "arm64":
		return fmt.Sprintf("etc-collector-%s-darwin-arm64.tar.gz", version), nil
	default:
		return "", newErr(CodeVersionNotFound,
			fmt.Sprintf("no published release artifact for %s/%s", goos, goarch),
			"This platform is not published. Build from source, or use --download-url with your own binary.", nil)
	}
}

// fetchChecksums downloads <repo>/releases/download/<tag>/checksums.sha256 and
// parses the standard `sha256sum` output format ("<hex>  <filename>" per
// line) into a name→hex map. Uses the client's normal redirect-following
// behavior - checksums.sha256 is a few hundred bytes, capped defensively.
func fetchChecksums(ctx context.Context, client *http.Client, repo, tag string) (map[string]string, error) {
	url := githubBaseURL + "/" + repo + "/releases/download/" + tag + "/checksums.sha256"
	cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(cctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, newErr(CodeNetworkUnreachable, "build checksums request failed", "Re-run the upgrade.", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, newErr(CodeNetworkUnreachable,
			"checksums.sha256 unreachable: "+url,
			"Check network/proxy. Test: curl -IL "+url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, newErr(CodeNetworkUnreachable,
			fmt.Sprintf("checksums.sha256 HTTP %d for tag %s", resp.StatusCode, tag),
			"Verify the tag/version exists as a release, or pass --version explicitly.", nil)
	}

	sums := make(map[string]string)
	scanner := bufio.NewScanner(io.LimitReader(resp.Body, 1<<20)) // 1 MB cap
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) != 2 {
			continue
		}
		sums[fields[1]] = fields[0]
	}
	if err := scanner.Err(); err != nil {
		return nil, newErr(CodeNetworkUnreachable, "read checksums body failed", "Re-run the upgrade.", err)
	}
	return sums, nil
}

// resolveGitHubRelease is the default (no --manifest-url) upgrade source: it
// resolves a version straight against DefaultReleasesRepo's releases, with no
// manifest.json in the loop at all.
func resolveGitHubRelease(ctx context.Context, client *http.Client, requested string) (version, url, sha string, err error) {
	var tag string
	if requested == "" || strings.EqualFold(requested, "latest") {
		tag, err = resolveLatestTag(ctx, client, DefaultReleasesRepo)
		if err != nil {
			return "", "", "", err
		}
	} else {
		tag = "v" + strings.TrimPrefix(requested, "v")
	}
	version = strings.TrimPrefix(tag, "v")

	asset, err := releaseAssetName(version, runtime.GOOS, runtime.GOARCH)
	if err != nil {
		return version, "", "", err
	}

	sums, err := fetchChecksums(ctx, client, DefaultReleasesRepo, tag)
	if err != nil {
		return version, "", "", err
	}
	sha, ok := sums[asset]
	if !ok {
		return version, "", "", newErr(CodeVersionNotFound,
			fmt.Sprintf("checksums.sha256 for %s has no entry for %s", tag, asset),
			"The release may be incomplete, or this platform isn't published for that version.", nil)
	}

	url = githubBaseURL + "/" + DefaultReleasesRepo + "/releases/download/" + tag + "/" + asset
	return version, url, sha, nil
}
