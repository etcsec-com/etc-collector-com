package azure

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/etcsec-com/etc-collector/pkg/types"
)

// AZ_GROUP_NO_OWNER / AZ_GROUP_OWNER_IS_GUEST were retired for
// rendering count := 1 on every run with no owner data behind it.
// enrichGroupsWithOwners is the collection half of the fix: it populates
// AzureOwners / AzureOwnersProbed via GET /groups/{id}/owners, and
// AzureOwnersProbed must be true only for a group actually reached.

func TestEnrichGroupsWithOwners_PopulatesOwnersAndProbed(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"value":[
			{"id":"o1","displayName":"Alice Owner","userPrincipalName":"alice@corp.com"},
			{"id":"o2","displayName":"Bob Owner","userPrincipalName":"bob@corp.com"}
		]}`))
	}))
	defer server.Close()

	client := &Client{connected: true, cred: fakeTokenCredential{}, graphBaseURL: server.URL + "/"}
	grps := []types.Group{{DisplayName: "g1", ObjectSID: "id-1"}}
	client.enrichGroupsWithOwners(context.Background(), grps)

	if !grps[0].AzureOwnersProbed {
		t.Fatal("expected AzureOwnersProbed=true for a group actually reached")
	}
	want := []string{"alice@corp.com", "bob@corp.com"}
	if len(grps[0].AzureOwners) != len(want) {
		t.Fatalf("expected AzureOwners=%v, got %v", want, grps[0].AzureOwners)
	}
	for i, w := range want {
		if grps[0].AzureOwners[i] != w {
			t.Fatalf("expected AzureOwners=%v, got %v", want, grps[0].AzureOwners)
		}
	}
}

// A group genuinely has no owner: AzureOwnersProbed must still flip true -
// that's what tells AZ_GROUP_NO_OWNER the empty list is a real answer, not
// an unasked question.
func TestEnrichGroupsWithOwners_EmptyOwnerListStillMarkedProbed(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"value":[]}`))
	}))
	defer server.Close()

	client := &Client{connected: true, cred: fakeTokenCredential{}, graphBaseURL: server.URL + "/"}
	grps := []types.Group{{DisplayName: "g1", ObjectSID: "id-1"}}
	client.enrichGroupsWithOwners(context.Background(), grps)

	if !grps[0].AzureOwnersProbed {
		t.Fatal("expected AzureOwnersProbed=true even when the owner list came back empty")
	}
	if len(grps[0].AzureOwners) != 0 {
		t.Fatalf("expected no owners, got %v", grps[0].AzureOwners)
	}
}

// Falls back to displayName only when userPrincipalName is absent (e.g. a
// non-user owner such as a service principal).
func TestEnrichGroupsWithOwners_FallsBackToDisplayName(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"value":[{"id":"sp1","displayName":"Some Service Principal"}]}`))
	}))
	defer server.Close()

	client := &Client{connected: true, cred: fakeTokenCredential{}, graphBaseURL: server.URL + "/"}
	grps := []types.Group{{DisplayName: "g1", ObjectSID: "id-1"}}
	client.enrichGroupsWithOwners(context.Background(), grps)

	if len(grps[0].AzureOwners) != 1 || grps[0].AzureOwners[0] != "Some Service Principal" {
		t.Fatalf("expected AzureOwners=[Some Service Principal], got %v", grps[0].AzureOwners)
	}
}

// A group the transport failed to reach must be left AzureOwnersProbed=false
// - never a fabricated empty-owners answer.
func TestEnrichGroupsWithOwners_TransportFailureLeavesGroupUnprobed(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":{"message":"Insufficient privileges"}}`))
	}))
	defer server.Close()

	client := &Client{connected: true, cred: fakeTokenCredential{}, graphBaseURL: server.URL + "/"}
	grps := []types.Group{{DisplayName: "g1", ObjectSID: "id-1"}}
	client.enrichGroupsWithOwners(context.Background(), grps)

	if grps[0].AzureOwnersProbed {
		t.Fatal("expected AzureOwnersProbed=false after a transport failure")
	}
	if grps[0].AzureOwners != nil {
		t.Fatalf("expected no owners recorded on failure, got %v", grps[0].AzureOwners)
	}
}

// Each group is queried at its own /groups/{id}/owners endpoint - not one
// shared list call - and a group with no ObjectSID (never a real case, but
// defensive) is skipped rather than sent to a malformed URL.
func TestEnrichGroupsWithOwners_PerGroupEndpointRouting(t *testing.T) {
	seen := make(map[string]bool)
	var mu sync.Mutex
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen[r.URL.Path] = true
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"value":[]}`))
	}))
	defer server.Close()

	client := &Client{connected: true, cred: fakeTokenCredential{}, graphBaseURL: server.URL + "/"}
	grps := []types.Group{
		{DisplayName: "g1", ObjectSID: "id-1"},
		{DisplayName: "g2", ObjectSID: "id-2"},
		{DisplayName: "g-no-id", ObjectSID: ""},
	}
	client.enrichGroupsWithOwners(context.Background(), grps)

	for _, id := range []string{"id-1", "id-2"} {
		path := fmt.Sprintf("/v1.0/groups/%s/owners", id)
		if !seen[path] {
			t.Fatalf("expected a request to %s, saw %v", path, seen)
		}
	}
	if grps[2].AzureOwnersProbed {
		t.Fatal("expected the group with no ObjectSID to be skipped, never probed")
	}
}

// A budget that has already expired (modeled here via an already-cancelled
// parent context, which context.WithTimeout can only ever narrow further)
// must leave every group unprobed rather than block or fabricate data -
// this is the same deadline plumbing that bounds a 999-group tenant.
func TestEnrichGroupsWithOwners_ExpiredBudgetLeavesGroupsUnprobed(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"value":[{"userPrincipalName":"alice@corp.com"}]}`))
	}))
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already expired before enrichGroupsWithOwners even starts

	client := &Client{connected: true, cred: fakeTokenCredential{}, graphBaseURL: server.URL + "/"}
	grps := []types.Group{{DisplayName: "g1", ObjectSID: "id-1"}}
	client.enrichGroupsWithOwners(ctx, grps)

	if grps[0].AzureOwnersProbed {
		t.Fatal("expected AzureOwnersProbed=false when the budget is already exhausted")
	}
}
