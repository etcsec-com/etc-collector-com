package azure

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// AZ_SELF_SERVICE_GROUPS_OPEN read
// AzureTenantConfig.GroupUnifiedCreationPolicy (self-service M365/Teams
// group creation), but no provider call ever populated it: GetTenantConfig
// never queried /groups/settings (the Group.Unified directory setting
// template), so the field stayed at its zero value and the detector treated
// "unmeasured" as "open" on every tenant.

func TestGetGroupCreationPolicyUnlocked(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{
			name: "EnableGroupCreation true",
			body: `{"value":[{"templateId":"62375ab9-6b52-47ed-826b-58e47e0e304b","values":[{"name":"EnableGroupCreation","value":"true"}]}]}`,
			want: "Open",
		},
		{
			name: "EnableGroupCreation false",
			body: `{"value":[{"templateId":"62375ab9-6b52-47ed-826b-58e47e0e304b","values":[{"name":"EnableGroupCreation","value":"false"}]}]}`,
			want: "Restricted",
		},
		{
			name: "no Group.Unified override -> tenant default (Open)",
			body: `{"value":[]}`,
			want: "Open",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(tc.body))
			}))
			defer server.Close()

			client := &Client{connected: true, cred: fakeTokenCredential{}, graphBaseURL: server.URL + "/"}
			got, err := client.getGroupCreationPolicyUnlocked(context.Background())
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestGetGroupCreationPolicyUnlocked_Error(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()

	client := &Client{connected: true, cred: fakeTokenCredential{}, graphBaseURL: server.URL + "/"}
	_, err := client.getGroupCreationPolicyUnlocked(context.Background())
	if err == nil {
		t.Fatal("expected an error on a Graph failure, so GetTenantConfig leaves the field unknown rather than guessing")
	}
}
