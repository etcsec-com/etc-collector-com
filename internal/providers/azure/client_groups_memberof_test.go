package azure

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/etcsec-com/etc-collector/pkg/types"
)

// AZ_GROUP_NESTED_PRIVILEGED: convertAzureGroup never
// populated MemberOf for Azure-sourced groups (GetGroups never called
// /memberOf), so the detector's len(group.MemberOf) > 0 leg was always
// false.

func TestEnrichGroupsWithParentGroups_PopulatesMemberOf(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"value":[{"id":"parent-group-1"}]}`))
	}))
	defer server.Close()

	client := &Client{connected: true, cred: fakeTokenCredential{}, graphBaseURL: server.URL + "/"}
	grps := []types.Group{{DisplayName: "g1", ObjectSID: "id-1"}}
	client.enrichGroupsWithParentGroups(context.Background(), grps)

	if len(grps[0].MemberOf) != 1 || grps[0].MemberOf[0] != "parent-group-1" {
		t.Fatalf("expected MemberOf=[parent-group-1], got %v", grps[0].MemberOf)
	}
}

func TestEnrichGroupsWithParentGroups_NoParents(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"value":[]}`))
	}))
	defer server.Close()

	client := &Client{connected: true, cred: fakeTokenCredential{}, graphBaseURL: server.URL + "/"}
	grps := []types.Group{{DisplayName: "g1", ObjectSID: "id-1"}}
	client.enrichGroupsWithParentGroups(context.Background(), grps)

	if grps[0].MemberOf != nil {
		t.Fatalf("expected nil MemberOf for a top-level group, got %v", grps[0].MemberOf)
	}
}
