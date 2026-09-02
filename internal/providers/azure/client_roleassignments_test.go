package azure

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	msgraphsdk "github.com/microsoftgraph/msgraph-sdk-go"
)

// B_156/T_058 — /roleManagement/directory/roleAssignments rejects a request
// that expands more than one navigation property, confirmed live against a
// real tenant on 2026-08-26 ("Only one property can be expanded in a single
// query"). The fake server below reproduces that exact validation so these
// tests exercise the real defect shape without a live tenant.

// fakeTokenCredential satisfies azcore.TokenCredential without any network
// call — GetRoleAssignments never touches the Graph SDK client itself, only
// the raw HTTP path, so a dummy token is enough to exercise it.
type fakeTokenCredential struct{}

func (fakeTokenCredential) GetToken(context.Context, policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return azcore.AccessToken{Token: "fake-token", ExpiresOn: time.Now().Add(time.Hour)}, nil
}

// splitTopLevelExpand splits a $expand value on commas that sit outside any
// nested ($select=...) parens, so "principal(...),roleDefinition(...)"
// counts as two targets while "principal($select=a,b,c)" counts as one.
func splitTopLevelExpand(expand string) []string {
	if expand == "" {
		return nil
	}
	var parts []string
	depth, start := 0, 0
	for i, r := range expand {
		switch r {
		case '(':
			depth++
		case ')':
			depth--
		case ',':
			if depth == 0 {
				parts = append(parts, expand[start:i])
				start = i + 1
			}
		}
	}
	parts = append(parts, expand[start:])
	return parts
}

// newFakeRoleAssignmentsServer mimics the single-expand constraint of the
// real endpoint. Any other path (the PIM sibling endpoints GetRoleAssignments
// also calls) 404s, matching their documented soft-fail-to-empty behavior.
func newFakeRoleAssignmentsServer(t *testing.T, seenQueries *[]string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/roleManagement/directory/roleAssignments") {
			http.NotFound(w, r)
			return
		}
		if seenQueries != nil {
			*seenQueries = append(*seenQueries, r.URL.RawQuery)
		}

		expand, err := url.QueryUnescape(r.URL.Query().Get("$expand"))
		if err != nil {
			t.Fatalf("bad $expand encoding: %v", err)
		}
		targets := splitTopLevelExpand(expand)

		w.Header().Set("Content-Type", "application/json")
		if len(targets) > 1 {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":{"code":"Request_BadRequest","message":"Only one property can be expanded in a single query."}}`))
			return
		}

		switch {
		case len(targets) == 1 && strings.HasPrefix(targets[0], "roleDefinition"):
			_, _ = w.Write([]byte(`{"value":[{"id":"assign-1","roleDefinition":{"id":"62e90394-69f5-4237-9190-012177145e10","displayName":"Global Administrator"}}]}`))
		case len(targets) == 1 && strings.HasPrefix(targets[0], "principal"):
			_, _ = w.Write([]byte(`{"value":[{"id":"assign-1","principalId":"user-1","roleDefinitionId":"62e90394-69f5-4237-9190-012177145e10","directoryScopeId":"/","principal":{"@odata.type":"#microsoft.graph.user","displayName":"Test Admin","userPrincipalName":"test.admin@contoso.test","mail":"test.admin@contoso.test","jobTitle":"IT","department":"IT Ops"}}]}`))
		default:
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":{"code":"Request_BadRequest","message":"unexpected $expand in test"}}`))
		}
	}))
}

// TestRoleAssignmentsEndpoint_DoubleExpandRejected pins the historical defect:
// the exact query string GetRoleAssignments used to send (both principal and
// roleDefinition expanded, each with a nested $select) gets HTTP 400 from a
// server that enforces the real constraint — this is "the current form of
// the request", failing, as the acceptance criterion asks for.
func TestRoleAssignmentsEndpoint_DoubleExpandRejected(t *testing.T) {
	server := newFakeRoleAssignmentsServer(t, nil)
	defer server.Close()

	resp, err := http.Get(server.URL +
		"/v1.0/roleManagement/directory/roleAssignments?$expand=principal($select=id,displayName,userPrincipalName,mail,jobTitle,department),roleDefinition($select=id,displayName)")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected HTTP 400 on the pre-fix double-expand query, got %d", resp.StatusCode)
	}
	var body struct {
		Error struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode error body: %v", err)
	}
	if !strings.Contains(body.Error.Message, "Only one property can be expanded") {
		t.Fatalf("unexpected error message: %q", body.Error.Message)
	}
}

// TestGetRoleAssignments_SplitExpandSucceeds proves the fix: against a server
// that enforces the exact single-expand constraint documented on
// GetRoleAssignments, the corrected client call succeeds and merges the
// principal pass with the roleDefinition pass into a complete RoleAssignment.
func TestGetRoleAssignments_SplitExpandSucceeds(t *testing.T) {
	var seenQueries []string
	server := newFakeRoleAssignmentsServer(t, &seenQueries)
	defer server.Close()

	graphClient, err := msgraphsdk.NewGraphServiceClientWithCredentials(fakeTokenCredential{}, []string{
		"https://graph.microsoft.com/.default",
	})
	if err != nil {
		t.Fatalf("build graph client: %v", err)
	}

	client := &Client{
		connected:    true,
		graphClient:  graphClient,
		cred:         fakeTokenCredential{},
		graphBaseURL: server.URL + "/",
	}

	assignments, err := client.GetRoleAssignments(context.Background())
	if err != nil {
		t.Fatalf("GetRoleAssignments returned an error: %v", err)
	}
	if len(assignments) != 1 {
		t.Fatalf("expected 1 assignment, got %d: %+v", len(assignments), assignments)
	}

	a := assignments[0]
	if a.RoleName != "Global Administrator" {
		t.Errorf("RoleName = %q, want %q (from the roleDefinition pass)", a.RoleName, "Global Administrator")
	}
	if a.RoleID != "62e90394-69f5-4237-9190-012177145e10" {
		t.Errorf("RoleID = %q, want the Global Administrator role definition id", a.RoleID)
	}
	if a.PrincipalName != "Test Admin" {
		t.Errorf("PrincipalName = %q, want %q (from the principal pass)", a.PrincipalName, "Test Admin")
	}
	if a.Mail != "test.admin@contoso.test" {
		t.Errorf("Mail = %q, want the principal's mail — this field feeds unresolved-members.go", a.Mail)
	}
	if a.AssignmentType != "direct" || !a.IsPermanent || a.IsEligible {
		t.Errorf("expected a direct/permanent assignment (no PIM eligibility in this fixture), got AssignmentType=%q IsPermanent=%v IsEligible=%v",
			a.AssignmentType, a.IsPermanent, a.IsEligible)
	}

	// Regression guard: each request this call made to the roleAssignments
	// endpoint must expand exactly one navigation property. If this ever
	// goes back to expanding both in one call, this fails alongside a live
	// audit — exactly the gap that let the original bug hide for 5 months.
	for _, q := range seenQueries {
		values, err := url.ParseQuery(q)
		if err != nil {
			t.Fatalf("unparsable query %q: %v", q, err)
		}
		expand, err := url.QueryUnescape(values.Get("$expand"))
		if err != nil {
			t.Fatalf("bad $expand encoding in %q: %v", q, err)
		}
		if n := len(splitTopLevelExpand(expand)); n != 1 {
			t.Errorf("query %q expands %d navigation properties, want exactly 1", q, n)
		}
	}
}
