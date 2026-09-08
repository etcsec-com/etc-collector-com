package registrations

import (
	"context"
	"strings"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// TestAppReplyURLWildcard_DescriptionScopedToWebPlatform mirrors the
// APP_REPLY_URL_HTTP fix: the description must not claim coverage this
// detector doesn't have (SPA/publicClient redirect URIs aren't collected).
func TestAppReplyURLWildcard_DescriptionScopedToWebPlatform(t *testing.T) {
	d := NewAppReplyURLWildcardDetector()
	f := d.Detect(context.Background(), &audit.DetectorData{})[0]

	if !strings.Contains(f.Description, "web platform") {
		t.Errorf("description must scope the claim to the web platform, got %q", f.Description)
	}
	if !strings.Contains(f.Description, "SPA") && !strings.Contains(f.Description, "not currently collected") {
		t.Errorf("description must disclose that SPA/public-client redirect URIs are not collected, got %q", f.Description)
	}
}

func TestAppReplyURLWildcard_FlagsWildcardURL(t *testing.T) {
	wildcardApp := types.AppRegistration{
		ID:          "11111111-1111-1111-1111-111111111111",
		DisplayName: "wildcard-app",
		ReplyURLs:   []string{"https://*.example.com/callback"},
	}
	cleanApp := types.AppRegistration{
		ID:          "22222222-2222-2222-2222-222222222222",
		DisplayName: "clean-app",
		ReplyURLs:   []string{"https://app.example.com/callback"},
	}

	d := NewAppReplyURLWildcardDetector()
	data := &audit.DetectorData{
		AzureAppRegistrations: []types.AppRegistration{wildcardApp, cleanApp},
		IncludeDetails:        true,
	}

	f := d.Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("expected only the wildcard app flagged, got count %d", f.Count)
	}
	if f.AffectedEntities[0].DisplayName != "wildcard-app" {
		t.Errorf("expected wildcard-app flagged, got %q", f.AffectedEntities[0].DisplayName)
	}
}
