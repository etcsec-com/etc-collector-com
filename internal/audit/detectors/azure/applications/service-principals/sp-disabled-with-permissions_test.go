package serviceprincipals

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// TestSPDisabledWithPermissions_JoinsOnObjectID reproduces a real tenant shape:
// a disabled SP whose OAuth2 grant references it by ObjectId (per Microsoft
// Graph's oauth2PermissionGrant.clientId semantics), not by AppId. Before the
// fix, the detector indexed service principals by AppID and looked up
// grant.ClientID (an ObjectId) in that map, so the lookup always missed.
func TestSPDisabledWithPermissions_JoinsOnObjectID(t *testing.T) {
	d := NewSPDisabledWithPermissionsDetector()
	data := &audit.DetectorData{
		AzureServicePrincipals: []types.ServicePrincipal{
			{
				ID:             "11111111-1111-1111-1111-111111111111", // ObjectId
				AppID:          "22222222-2222-2222-2222-222222222222", // AppId (distinct)
				DisplayName:    "legacy-integration-sp",
				AccountEnabled: false,
			},
		},
		AzureOAuth2PermissionGrants: []types.OAuth2PermissionGrant{
			{
				ID:       "grant-1",
				ClientID: "11111111-1111-1111-1111-111111111111", // matches SP ObjectId, not AppId
			},
		},
		IncludeDetails: true,
	}

	f := d.Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("expected 1 disabled SP with a permission grant (joined by ObjectId), got %d", f.Count)
	}
}
