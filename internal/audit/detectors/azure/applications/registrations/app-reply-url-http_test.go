package registrations

import (
	"context"
	"strings"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// TestAppReplyURLHTTP_DescriptionScopedToWebPlatform locks in that this
// detector no longer claims blanket "reply URLs" coverage: it only ever
// reads AppRegistration.ReplyURLs, which the collector populates from the
// web platform's redirectUris alone (SPA/publicClient redirect URIs are not
// collected). The description must say so rather than imply full coverage.
func TestAppReplyURLHTTP_DescriptionScopedToWebPlatform(t *testing.T) {
	d := NewAppReplyURLHTTPDetector()
	f := d.Detect(context.Background(), &audit.DetectorData{})[0]

	if !strings.Contains(f.Description, "web platform") {
		t.Errorf("description must scope the claim to the web platform, got %q", f.Description)
	}
	if !strings.Contains(f.Description, "SPA") && !strings.Contains(f.Description, "not currently collected") {
		t.Errorf("description must disclose that SPA/public-client redirect URIs are not collected, got %q", f.Description)
	}
}

func TestAppReplyURLHTTP_FlagsHTTPExcludingLocalhost(t *testing.T) {
	httpApp := types.AppRegistration{
		ID:          "11111111-1111-1111-1111-111111111111",
		DisplayName: "http-app",
		ReplyURLs:   []string{"http://example.com/callback"},
	}
	localhostApp := types.AppRegistration{
		ID:          "22222222-2222-2222-2222-222222222222",
		DisplayName: "localhost-app",
		ReplyURLs:   []string{"http://localhost:3000/callback"},
	}

	d := NewAppReplyURLHTTPDetector()
	data := &audit.DetectorData{
		AzureAppRegistrations: []types.AppRegistration{httpApp, localhostApp},
		IncludeDetails:        true,
	}

	f := d.Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("expected only the non-localhost HTTP app flagged, got count %d", f.Count)
	}
	if f.AffectedEntities[0].DisplayName != "http-app" {
		t.Errorf("expected http-app flagged, got %q", f.AffectedEntities[0].DisplayName)
	}
}
