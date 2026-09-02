package azure

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// B_158/T_058 — GetOrganizationPrivacyStatementURL and
// GetTermsOfUseAgreementsCount previously didn't exist: AZ_NO_PRIVACY_STATEMENT
// and AZ_NO_TERMS_OF_USE fired unconditionally with no data behind them.

func TestGetOrganizationPrivacyStatementURL_ConfiguredAndEmpty(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{
			name: "statement URL configured",
			body: `{"value":[{"privacyProfile":{"contactEmail":"privacy@contoso.test","statementUrl":"https://contoso.test/privacy"}}]}`,
			want: "https://contoso.test/privacy",
		},
		{
			name: "privacyProfile present but empty statementUrl",
			body: `{"value":[{"privacyProfile":{"contactEmail":"","statementUrl":""}}]}`,
			want: "",
		},
		{
			name: "privacyProfile entirely absent (Graph omits null fields)",
			body: `{"value":[{}]}`,
			want: "",
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
			got, err := client.GetOrganizationPrivacyStatementURL(context.Background())
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestGetTermsOfUseAgreementsCount(t *testing.T) {
	cases := []struct {
		name string
		body string
		want int
	}{
		{name: "no agreements", body: `{"value":[]}`, want: 0},
		{name: "two agreements", body: `{"value":[{"id":"a1"},{"id":"a2"}]}`, want: 2},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(tc.body))
			}))
			defer server.Close()

			client := &Client{connected: true, cred: fakeTokenCredential{}, graphBaseURL: server.URL + "/"}
			got, err := client.GetTermsOfUseAgreementsCount(context.Background())
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("got %d, want %d", got, tc.want)
			}
		})
	}
}
