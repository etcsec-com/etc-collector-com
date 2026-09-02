// Package azure provides an Azure AD / Entra ID client using Microsoft Graph
package azure

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	msgraphsdk "github.com/microsoftgraph/msgraph-sdk-go"
	"github.com/microsoftgraph/msgraph-sdk-go/applications"
	"github.com/microsoftgraph/msgraph-sdk-go/groups"
	"github.com/microsoftgraph/msgraph-sdk-go/models"
	"github.com/microsoftgraph/msgraph-sdk-go/serviceprincipals"
	"github.com/microsoftgraph/msgraph-sdk-go/users"

	"github.com/etcsec-com/etc-collector/internal/providers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// Config holds Azure AD connection configuration
type Config struct {
	TenantID     string `yaml:"tenantId"`
	ClientID     string `yaml:"clientId"`
	ClientSecret string `yaml:"clientSecret"`

	// Certificate authentication (client_assertion). Either of these
	// satisfies the credential requirement in place of ClientSecret, and
	// takes precedence over it — see newCredential in credential.go.
	//
	// ClientCertPath points at a PEM bundle (certificate + private key) or a
	// PKCS#12/.pfx file; ClientCertPEM carries the same PEM content inline for
	// callers that never write it to disk (SaaS/trial commands).
	// ClientCertPassword is only needed for an encrypted bundle.
	ClientCertPath     string `yaml:"clientCertPath"`
	ClientCertPEM      string `yaml:"clientCertPem"`
	ClientCertPassword string `yaml:"clientCertPassword"`
}

// Client implements the Provider interface for Azure AD / Entra ID
type Client struct {
	config      Config
	graphClient *msgraphsdk.GraphServiceClient
	mu          sync.RWMutex
	connected   bool
	tenantInfo  *TenantInfo

	// Token credential, built lazily and reused by both the Graph SDK client
	// and the raw HTTP path. Its own lock: c.mu is already held when Connect
	// asks for it.
	credMu sync.Mutex
	cred   azcore.TokenCredential

	// graphBaseURL overrides the Microsoft Graph host, e.g. "https://graph.microsoft.com/".
	// Empty (the zero value, and every production Client) means the real host.
	// White-box tests in this package point it at an httptest.Server to
	// reproduce real Graph validation errors (T_058) without a live tenant.
	graphBaseURL string
}

// TenantInfo contains Azure AD tenant information
type TenantInfo struct {
	TenantID    string
	DisplayName string
	Domain      string
}

// NewClient creates a new Azure AD client
func NewClient(cfg Config) (*Client, error) {
	if cfg.TenantID == "" {
		return nil, fmt.Errorf("tenant ID is required")
	}
	if cfg.ClientID == "" {
		return nil, fmt.Errorf("client ID is required")
	}
	if !cfg.HasCredential() {
		return nil, fmt.Errorf("a client secret or a client certificate is required (client secret, or a PEM/PKCS#12 certificate whose public part is registered on the Entra app)")
	}

	return &Client{
		config: cfg,
	}, nil
}

// Type returns the provider type
func (c *Client) Type() providers.ProviderType {
	return providers.ProviderTypeAzure
}

// Connect establishes a connection to Azure AD
func (c *Client) Connect(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.connected && c.graphClient != nil {
		return nil
	}

	// Create credential (client secret or client certificate — see credential.go)
	cred, err := c.credential()
	if err != nil {
		return providers.NewProviderError(providers.ProviderTypeAzure, "create credential", err)
	}

	// Create Graph client
	client, err := msgraphsdk.NewGraphServiceClientWithCredentials(cred, []string{
		"https://graph.microsoft.com/.default",
	})
	if err != nil {
		return providers.NewProviderError(providers.ProviderTypeAzure, "create client", err)
	}

	c.graphClient = client
	c.connected = true

	return nil
}

// Close closes the Azure AD connection
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.graphClient = nil
	c.connected = false
	return nil
}

// IsConnected returns true if connected
func (c *Client) IsConnected() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.connected && c.graphClient != nil
}

// GetUsers retrieves users from Azure AD with pagination support
func (c *Client) GetUsers(ctx context.Context, opts providers.QueryOptions) ([]types.User, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if !c.connected || c.graphClient == nil {
		return nil, fmt.Errorf("not connected")
	}

	var azureUsers []types.User

	// Build query - limit page size to 999 (Graph API max per page)
	pageSize := 999
	if opts.MaxResults > 0 && opts.MaxResults < 999 {
		pageSize = opts.MaxResults
	}

	requestConfig := &users.UsersRequestBuilderGetRequestConfiguration{
		QueryParameters: &users.UsersRequestBuilderGetQueryParameters{
			Select: []string{
				"id",
				"userPrincipalName",
				"displayName",
				"mail",
				"accountEnabled",
				"createdDateTime",
				"signInActivity", // Parent object containing lastSignInDateTime + lastNonInteractiveSignInDateTime
				"userType",
				"assignedLicenses",
				"usageLocation",         // For licensing compliance
				"proxyAddresses",        // Secondary email addresses
				"onPremisesSyncEnabled", // Hybrid sync status
				// v3.1.38 §2 — onPremises identifiers needed by audit.hybridLinks
				// to cross-ref Entra users with their AD source for hybrid
				// attack-path analysis. Cheap to add (~50 bytes/user max).
				"onPremisesDistinguishedName",
				"onPremisesSecurityIdentifier",
				"onPremisesImmutableId",
				"onPremisesSamAccountName",
				// v3.1.39 §2 — creationType powers audit.firstPartyAccounts
				// (Resource = Bookings/Forms accounts, EmailVerified = B2B
				// self-service signup, etc.).
				"creationType",
			},
			Top: int32Ptr(int32(pageSize)),
		},
	}

	if opts.Filter != "" {
		requestConfig.QueryParameters.Filter = &opts.Filter
	}

	// Pagination loop - follow @odata.nextLink until exhausted or limit reached
	var nextLink *string
	requestBuilder := c.graphClient.Users()

	for {
		var result models.UserCollectionResponseable
		var err error

		// Use WithUrl for subsequent pages, normal Get for first page
		if nextLink != nil && *nextLink != "" {
			result, err = requestBuilder.WithUrl(*nextLink).Get(ctx, nil)
		} else {
			result, err = requestBuilder.Get(ctx, requestConfig)
		}

		if err != nil {
			return nil, providers.NewProviderError(providers.ProviderTypeAzure, "get users", err)
		}

		// Process current page
		for _, u := range result.GetValue() {
			user := convertAzureUser(u)
			azureUsers = append(azureUsers, user)

			// Stop if we've reached the requested limit
			if opts.MaxResults > 0 && len(azureUsers) >= opts.MaxResults {
				return azureUsers, nil
			}
		}

		// Check for next page
		nextLink = result.GetOdataNextLink()
		if nextLink == nil || *nextLink == "" {
			break // No more pages
		}
	}

	// Enrich users with authentication method registration data
	authMethodsMap, err := c.GetAuthenticationMethodRegistrations(ctx)
	if err == nil && len(authMethodsMap) > 0 {
		for i := range azureUsers {
			upn := azureUsers[i].UserPrincipalName
			if upn == "" {
				continue
			}
			if methods, found := authMethodsMap[upn]; found {
				azureUsers[i].AzureAuthenticationMethods = methods
				// Set MfaRegistered based on presence of "mfa" in methods
				hasMfa := false
				for _, method := range methods {
					if method == "mfa" || strings.Contains(strings.ToLower(method), "mfa") {
						hasMfa = true
						break
					}
				}
				azureUsers[i].AzureMfaRegistered = &hasMfa
			}
		}
	}

	return azureUsers, nil
}

// GetAuthenticationMethodRegistrations retrieves authentication method registration details for all users
// Returns a map of userPrincipalName -> list of registered methods
// Requires AuditLog.Read.All or Reports.Read.All permission
func (c *Client) GetAuthenticationMethodRegistrations(ctx context.Context) (map[string][]string, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if !c.connected {
		return nil, fmt.Errorf("not connected")
	}

	methodsMap := make(map[string][]string)

	// Call /reports/credentialUserRegistrationDetails via HTTP direct
	// SDK doesn't support this endpoint yet
	body, err := c.callGraphHTTP(ctx, "GET", "/reports/credentialUserRegistrationDetails", nil)
	if err != nil {
		// If endpoint fails (missing permissions), return empty map to allow audit to continue
		// Log the error but don't fail the entire audit
		return methodsMap, nil
	}

	// Parse response
	var result struct {
		Value []struct {
			UserPrincipalName string   `json:"userPrincipalName"`
			IsMfaRegistered   bool     `json:"isMfaRegistered"`
			AuthMethods       []string `json:"authMethods"`
		} `json:"value"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		// Parsing error - return empty map
		return methodsMap, nil
	}

	// Build map of userPrincipalName -> authentication methods
	for _, user := range result.Value {
		if user.UserPrincipalName == "" {
			continue
		}

		var methods []string

		// Add MFA if registered
		if user.IsMfaRegistered {
			methods = append(methods, "mfa")
		}

		// Add specific auth methods
		for _, method := range user.AuthMethods {
			// Avoid duplicating "mfa" if already added
			if method != "" && method != "mfa" {
				methods = append(methods, method)
			}
		}

		if len(methods) > 0 {
			methodsMap[user.UserPrincipalName] = methods
		}
	}

	return methodsMap, nil
}

// MFARegistrationReport holds aggregated MFA registration counts from the
// /reports/authenticationMethods/userRegistrationDetails endpoint.
type MFARegistrationReport struct {
	MFACapableUsers    int
	MFARegisteredUsers int
	TotalUsers         int
}

// GetMFARegistrationReport queries the modern authentication methods user
// registration report and returns aggregated counts. Requires
// UserAuthenticationMethod.Read.All + AuditLog.Read.All.
func (c *Client) GetMFARegistrationReport(ctx context.Context) (*MFARegistrationReport, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if !c.connected {
		return nil, fmt.Errorf("not connected")
	}

	report := &MFARegistrationReport{}
	nextLink := "/reports/authenticationMethods/userRegistrationDetails?$top=999"

	for nextLink != "" {
		body, err := c.callGraphHTTP(ctx, "GET", nextLink, nil)
		if err != nil {
			return nil, err
		}

		var page struct {
			Value []struct {
				IsMfaCapable    bool `json:"isMfaCapable"`
				IsMfaRegistered bool `json:"isMfaRegistered"`
			} `json:"value"`
			NextLink string `json:"@odata.nextLink"`
		}
		if err := json.Unmarshal(body, &page); err != nil {
			return nil, err
		}

		for _, u := range page.Value {
			report.TotalUsers++
			if u.IsMfaCapable {
				report.MFACapableUsers++
			}
			if u.IsMfaRegistered {
				report.MFARegisteredUsers++
			}
		}

		if page.NextLink != "" {
			nextLink = strings.TrimPrefix(page.NextLink, "https://graph.microsoft.com/v1.0")
		} else {
			nextLink = ""
		}
	}

	return report, nil
}

// GetRoleEligibilitySchedules retrieves PIM-eligible role assignments
// Calls /roleManagement/directory/roleEligibilityScheduleInstances via HTTP direct
// Returns map of assignment ID -> eligibility details for later merging with active assignments
func (c *Client) GetRoleEligibilitySchedules(ctx context.Context) (map[string]types.RoleAssignment, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if !c.connected {
		return nil, fmt.Errorf("not connected")
	}

	eligibilityMap := make(map[string]types.RoleAssignment)

	// Call /roleManagement/directory/roleEligibilityScheduleInstances via HTTP direct
	// SDK doesn't fully support PIM endpoints yet
	body, err := c.callGraphHTTP(ctx, "GET", "/roleManagement/directory/roleEligibilityScheduleInstances?$expand=roleDefinition,principal", nil)
	if err != nil {
		// If endpoint fails (missing permissions or PIM not configured), return empty map
		// This allows audit to continue with standard role assignments only
		return eligibilityMap, nil
	}

	// Parse response
	var result struct {
		Value []struct {
			ID               string `json:"id"`
			PrincipalID      string `json:"principalId"`
			RoleDefinitionID string `json:"roleDefinitionId"`
			DirectoryScopeID string `json:"directoryScopeId"`
			MemberType       string `json:"memberType"` // direct, inherited
			StartDateTime    string `json:"startDateTime"`
			EndDateTime      string `json:"endDateTime"`
			RoleDefinition   struct {
				DisplayName string `json:"displayName"`
			} `json:"roleDefinition"`
			Principal struct {
				DisplayName string `json:"displayName"`
			} `json:"principal"`
		} `json:"value"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		// Parsing error - return empty map
		return eligibilityMap, nil
	}

	// Build map of principal+role -> eligibility details
	for _, item := range result.Value {
		if item.PrincipalID == "" || item.RoleDefinitionID == "" {
			continue
		}

		// Create a composite key: principalID + roleID + scope
		// This allows us to match with active assignments later
		key := item.PrincipalID + "|" + item.RoleDefinitionID + "|" + item.DirectoryScopeID

		assignment := types.RoleAssignment{
			ID:               item.ID,
			PrincipalID:      item.PrincipalID,
			RoleID:           item.RoleDefinitionID,
			DirectoryScopeID: item.DirectoryScopeID,
			RoleName:         item.RoleDefinition.DisplayName,
			PrincipalName:    item.Principal.DisplayName,
			AssignmentType:   "eligible",
			MemberType:       item.MemberType,
			IsEligible:       true,
			IsPermanent:      false, // Eligible assignments are not permanent
		}

		// Parse timestamps
		if item.StartDateTime != "" {
			if t, err := time.Parse(time.RFC3339, item.StartDateTime); err == nil {
				assignment.StartDateTime = t
			}
		}
		if item.EndDateTime != "" {
			if t, err := time.Parse(time.RFC3339, item.EndDateTime); err == nil {
				assignment.EndDateTime = t
			}
		}

		eligibilityMap[key] = assignment
	}

	return eligibilityMap, nil
}

// GetRoleAssignmentSchedules retrieves PIM-aware active role assignments
// from /roleManagement/directory/roleAssignmentSchedules. Unlike the legacy
// /roleAssignments endpoint, the Schedules view distinguishes "Assigned"
// (permanent) from "Activated" (currently active via PIM activation) via
// the assignmentType field — the distinction the SaaS drift timeline needs.
//
// Returns []RoleAssignment shaped like GetRoleAssignments so the existing
// downstream code paths consume it identically. CreatedDateTime is
// populated to drive the "since when permanent" timeline.
//
// Empty result + nil err on permission/PIM-not-configured failures so the
// audit can continue with the legacy active-role data.
func (c *Client) GetRoleAssignmentSchedules(ctx context.Context) ([]types.RoleAssignment, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if !c.connected {
		return nil, fmt.Errorf("not connected")
	}

	// Explicit $select for createdDateTime — Graph doesn't return it by
	// default on this endpoint, even though the schema documents it.
	// Without it, the SaaS drift timeline ("permanent since when?") loses
	// its core signal.
	selectFields := "id,principalId,roleDefinitionId,directoryScopeId,assignmentType,memberType,createdDateTime,modifiedDateTime,scheduleInfo,status"
	endpoint := "/roleManagement/directory/roleAssignmentSchedules?$select=" + selectFields + "&$expand=principal,roleDefinition&$top=999"
	var out []types.RoleAssignment
	for endpoint != "" {
		body, err := c.callGraphHTTP(ctx, "GET", endpoint, nil)
		if err != nil {
			return out, nil // soft fail — let audit continue
		}
		var page struct {
			Value []struct {
				ID               string `json:"id"`
				PrincipalID      string `json:"principalId"`
				RoleDefinitionID string `json:"roleDefinitionId"`
				DirectoryScopeID string `json:"directoryScopeId"`
				AssignmentType   string `json:"assignmentType"` // Assigned | Activated
				MemberType       string `json:"memberType"`
				CreatedDateTime  string `json:"createdDateTime"`
				ScheduleInfo     *struct {
					StartDateTime string `json:"startDateTime"`
					Expiration    *struct {
						EndDateTime string `json:"endDateTime"`
					} `json:"expiration"`
				} `json:"scheduleInfo"`
				Principal struct {
					DisplayName       string `json:"displayName"`
					UserPrincipalName string `json:"userPrincipalName"`
				} `json:"principal"`
				RoleDefinition struct {
					DisplayName string `json:"displayName"`
				} `json:"roleDefinition"`
			} `json:"value"`
			NextLink string `json:"@odata.nextLink"`
		}
		if jerr := json.Unmarshal(body, &page); jerr != nil {
			return out, nil
		}
		for _, item := range page.Value {
			ra := types.RoleAssignment{
				ID:                item.ID,
				PrincipalID:       item.PrincipalID,
				PrincipalName:     item.Principal.DisplayName,
				UserPrincipalName: item.Principal.UserPrincipalName,
				RoleID:            item.RoleDefinitionID,
				RoleName:          item.RoleDefinition.DisplayName,
				DirectoryScopeID:  item.DirectoryScopeID,
				AssignmentType:    item.AssignmentType,
				MemberType:        item.MemberType,
				IsPermanent:       item.AssignmentType == "Assigned",
			}
			if item.CreatedDateTime != "" {
				if t, err := time.Parse(time.RFC3339, item.CreatedDateTime); err == nil {
					ra.CreatedDateTime = t
				}
			}
			if item.ScheduleInfo != nil {
				if item.ScheduleInfo.StartDateTime != "" {
					if t, err := time.Parse(time.RFC3339, item.ScheduleInfo.StartDateTime); err == nil {
						ra.StartDateTime = t
					}
				}
				if item.ScheduleInfo.Expiration != nil && item.ScheduleInfo.Expiration.EndDateTime != "" {
					if t, err := time.Parse(time.RFC3339, item.ScheduleInfo.Expiration.EndDateTime); err == nil {
						ra.EndDateTime = t
					}
				}
			}
			out = append(out, ra)
		}
		if page.NextLink != "" {
			endpoint = strings.TrimPrefix(page.NextLink, "https://graph.microsoft.com/v1.0")
			if endpoint == page.NextLink {
				break // unrecognised host — stop pagination
			}
		} else {
			endpoint = ""
		}
	}
	return out, nil
}

// GetRoleAssignmentScheduleRequests fetches the last `days` days of PIM
// activation requests from /roleManagement/directory/roleAssignmentScheduleRequests.
// Each entry is one PIM action: selfActivate, selfDeactivate, adminAssign,
// adminUpdate, adminRemove, adminRenew, adminExtend.
//
// Powers audit.pimActivationHistory — the SaaS drift timeline + ITSM
// correlation (via ticketInfo.ticketNumber/ticketSystem). Empty result +
// nil err on failure so the audit can continue.
func (c *Client) GetRoleAssignmentScheduleRequests(ctx context.Context, days int) ([]types.PIMScheduleRequest, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if !c.connected {
		return nil, fmt.Errorf("not connected")
	}
	if days <= 0 {
		days = 90
	}

	since := time.Now().UTC().Add(-time.Duration(days) * 24 * time.Hour).Format(time.RFC3339)
	filter := url.QueryEscape("createdDateTime ge " + since)
	endpoint := "/roleManagement/directory/roleAssignmentScheduleRequests?$expand=principal,roleDefinition&$top=999&$filter=" + filter

	var out []types.PIMScheduleRequest
	for endpoint != "" {
		body, err := c.callGraphHTTP(ctx, "GET", endpoint, nil)
		if err != nil {
			return out, nil // soft fail — see callers' warning
		}
		var page struct {
			Value []struct {
				ID                string `json:"id"`
				Action            string `json:"action"`
				PrincipalID       string `json:"principalId"`
				RoleDefinitionID  string `json:"roleDefinitionId"`
				DirectoryScopeID  string `json:"directoryScopeId"`
				Justification     string `json:"justification"`
				Status            string `json:"status"`
				CreatedDateTime   string `json:"createdDateTime"`
				CompletedDateTime string `json:"completedDateTime"`
				TicketInfo        *struct {
					TicketNumber string `json:"ticketNumber"`
					TicketSystem string `json:"ticketSystem"`
				} `json:"ticketInfo"`
				Principal struct {
					DisplayName       string `json:"displayName"`
					UserPrincipalName string `json:"userPrincipalName"`
				} `json:"principal"`
				RoleDefinition struct {
					DisplayName string `json:"displayName"`
				} `json:"roleDefinition"`
			} `json:"value"`
			NextLink string `json:"@odata.nextLink"`
		}
		if jerr := json.Unmarshal(body, &page); jerr != nil {
			return out, nil
		}
		for _, item := range page.Value {
			req := types.PIMScheduleRequest{
				ID:               item.ID,
				Action:           item.Action,
				PrincipalID:      item.PrincipalID,
				PrincipalUpn:     item.Principal.UserPrincipalName,
				PrincipalName:    item.Principal.DisplayName,
				RoleID:           item.RoleDefinitionID,
				RoleDisplayName:  item.RoleDefinition.DisplayName,
				DirectoryScopeID: item.DirectoryScopeID,
				Justification:    item.Justification,
				Status:           item.Status,
			}
			if item.TicketInfo != nil {
				req.TicketNumber = item.TicketInfo.TicketNumber
				req.TicketSystem = item.TicketInfo.TicketSystem
			}
			if item.CreatedDateTime != "" {
				if t, err := time.Parse(time.RFC3339, item.CreatedDateTime); err == nil {
					req.CreatedDateTime = &t
				}
			}
			if item.CompletedDateTime != "" {
				if t, err := time.Parse(time.RFC3339, item.CompletedDateTime); err == nil {
					req.CompletedDateTime = &t
				}
			}
			out = append(out, req)
		}
		if page.NextLink != "" {
			endpoint = strings.TrimPrefix(page.NextLink, "https://graph.microsoft.com/v1.0")
			if endpoint == page.NextLink {
				break
			}
		} else {
			endpoint = ""
		}
	}
	return out, nil
}

// GetCrossTenantAccessPolicyDefault retrieves the tenant-wide default
// cross-tenant access policy from /policies/crossTenantAccessPolicy/default.
// Best-effort: 403/404 returns nil + nil (so the audit continues without
// the cross-tenant section).
//
// Powers audit.crossTenantAccess.default — the SaaS analyzer cross-references
// this with the binary B2B_INBOUND_TRUST_ALL / B2B_DIRECT_CONNECT_ENABLED
// findings to produce the per-partner trust map and concrete remediation
// recommendations.
func (c *Client) GetCrossTenantAccessPolicyDefault(ctx context.Context) (*types.CrossTenantDefaultPolicy, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if !c.connected {
		return nil, fmt.Errorf("not connected")
	}
	body, err := c.callGraphHTTP(ctx, "GET", "/policies/crossTenantAccessPolicy/default", nil)
	if err != nil {
		return nil, nil // soft fail
	}
	var raw crossTenantPolicyRaw
	if jerr := json.Unmarshal(body, &raw); jerr != nil {
		return nil, nil
	}
	def := &types.CrossTenantDefaultPolicy{
		B2BCollaboration:   convertCrossTenantChannels(raw.B2BCollaborationInbound, raw.B2BCollaborationOutbound),
		B2BDirectConnect:   convertCrossTenantChannels(raw.B2BDirectConnectInbound, raw.B2BDirectConnectOutbound),
		InboundTrust:       convertCrossTenantInboundTrust(raw.InboundTrust),
		TenantRestrictions: convertCrossTenantTenantRestrictions(raw.TenantRestrictions),
	}
	return def, nil
}

// GetCrossTenantAccessPolicyPartners retrieves all per-partner cross-tenant
// configurations from /policies/crossTenantAccessPolicy/partners. Paginated
// via @odata.nextLink. Best-effort like the default endpoint.
func (c *Client) GetCrossTenantAccessPolicyPartners(ctx context.Context) ([]types.CrossTenantPartnerPolicy, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if !c.connected {
		return nil, fmt.Errorf("not connected")
	}

	endpoint := "/policies/crossTenantAccessPolicy/partners?$top=999"
	var out []types.CrossTenantPartnerPolicy
	for endpoint != "" {
		body, err := c.callGraphHTTP(ctx, "GET", endpoint, nil)
		if err != nil {
			return out, nil
		}
		var page struct {
			Value []struct {
				crossTenantPolicyRaw
				TenantID                     string `json:"tenantId"`
				IsServiceProvider            *bool  `json:"isServiceProvider"`
				IsInMultiTenantOrganization  *bool  `json:"isInMultiTenantOrganization"`
				AutomaticUserConsentSettings *struct {
					InboundAllowed  *bool `json:"inboundAllowed"`
					OutboundAllowed *bool `json:"outboundAllowed"`
				} `json:"automaticUserConsentSettings"`
			} `json:"value"`
			NextLink string `json:"@odata.nextLink"`
		}
		if jerr := json.Unmarshal(body, &page); jerr != nil {
			return out, nil
		}
		for _, p := range page.Value {
			pp := types.CrossTenantPartnerPolicy{
				TenantID:         p.TenantID,
				B2BCollaboration: convertCrossTenantChannels(p.B2BCollaborationInbound, p.B2BCollaborationOutbound),
				B2BDirectConnect: convertCrossTenantChannels(p.B2BDirectConnectInbound, p.B2BDirectConnectOutbound),
				InboundTrust:     convertCrossTenantInboundTrust(p.InboundTrust),
			}
			if p.IsServiceProvider != nil {
				pp.IsServiceProvider = *p.IsServiceProvider
			}
			if p.IsInMultiTenantOrganization != nil {
				pp.IsInMultiTenantOrg = *p.IsInMultiTenantOrganization
			}
			if p.AutomaticUserConsentSettings != nil {
				if p.AutomaticUserConsentSettings.InboundAllowed != nil {
					pp.AutomaticUserConsent.InboundAllowed = *p.AutomaticUserConsentSettings.InboundAllowed
				}
				if p.AutomaticUserConsentSettings.OutboundAllowed != nil {
					pp.AutomaticUserConsent.OutboundAllowed = *p.AutomaticUserConsentSettings.OutboundAllowed
				}
			}
			out = append(out, pp)
		}
		if page.NextLink != "" {
			endpoint = strings.TrimPrefix(page.NextLink, "https://graph.microsoft.com/v1.0")
			if endpoint == page.NextLink {
				break
			}
		} else {
			endpoint = ""
		}
	}
	return out, nil
}

// GetMultiTenantOrganization detects whether the tenant is part of a
// Microsoft 365 Multi-Tenant Organization (feature 2024+). Best-effort:
// returns nil + nil when the tenant hasn't enabled MTO (404), so the
// audit doesn't choke on tenants that don't use this feature.
func (c *Client) GetMultiTenantOrganization(ctx context.Context) (*types.CrossTenantMultiTenantOrg, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if !c.connected {
		return nil, fmt.Errorf("not connected")
	}
	body, err := c.callGraphHTTP(ctx, "GET", "/tenantRelationships/multiTenantOrganization", nil)
	if err != nil {
		return nil, nil
	}
	var raw struct {
		State       string `json:"state"` // active | inactive | pending | etc.
		DisplayName string `json:"displayName"`
	}
	if jerr := json.Unmarshal(body, &raw); jerr != nil {
		return nil, nil
	}
	out := &types.CrossTenantMultiTenantOrg{
		IsEnabled: strings.EqualFold(raw.State, "active"),
	}
	// Member tenant count — best-effort, silent on failure.
	tBody, tErr := c.callGraphHTTP(ctx, "GET", "/tenantRelationships/multiTenantOrganization/tenants?$top=999", nil)
	if tErr == nil {
		var tPage struct {
			Value []struct {
				TenantID string `json:"tenantId"`
			} `json:"value"`
		}
		if json.Unmarshal(tBody, &tPage) == nil {
			out.TenantsCount = len(tPage.Value)
		}
	}
	return out, nil
}

// crossTenantPolicyRaw is the shared inbound/outbound shape between the
// default policy and per-partner overrides. Pointer types let us preserve
// "field absent" vs "field set to false" semantics on flag bools.
type crossTenantPolicyRaw struct {
	B2BCollaborationInbound  *crossTenantAccessChannelRaw      `json:"b2bCollaborationInbound"`
	B2BCollaborationOutbound *crossTenantAccessChannelRaw      `json:"b2bCollaborationOutbound"`
	B2BDirectConnectInbound  *crossTenantAccessChannelRaw      `json:"b2bDirectConnectInbound"`
	B2BDirectConnectOutbound *crossTenantAccessChannelRaw      `json:"b2bDirectConnectOutbound"`
	InboundTrust             *crossTenantInboundTrustRaw       `json:"inboundTrust"`
	TenantRestrictions       *crossTenantTenantRestrictionsRaw `json:"tenantRestrictions"`
}

type crossTenantAccessChannelRaw struct {
	UsersAndGroups *crossTenantAccessTargetRaw `json:"usersAndGroups"`
	Applications   *crossTenantAccessTargetRaw `json:"applications"`
}

type crossTenantAccessTargetRaw struct {
	AccessType string `json:"accessType"`
	Targets    []struct {
		Target     string `json:"target"`
		TargetType string `json:"targetType"`
	} `json:"targets"`
}

type crossTenantInboundTrustRaw struct {
	IsMfaAccepted                       *bool `json:"isMfaAccepted"`
	IsCompliantDeviceAccepted           *bool `json:"isCompliantDeviceAccepted"`
	IsHybridAzureADJoinedDeviceAccepted *bool `json:"isHybridAzureADJoinedDeviceAccepted"`
}

type crossTenantTenantRestrictionsRaw struct {
	UsersAndGroups *crossTenantAccessTargetRaw `json:"usersAndGroups"`
	Applications   *crossTenantAccessTargetRaw `json:"applications"`
}

func convertCrossTenantTarget(r *crossTenantAccessTargetRaw) types.CrossTenantAccessTarget {
	if r == nil {
		return types.CrossTenantAccessTarget{}
	}
	out := types.CrossTenantAccessTarget{AccessType: r.AccessType}
	for _, t := range r.Targets {
		// Targets are objects in the Graph payload but the SaaS analyzer
		// only needs the identifier (group ID / "AllUsers" / "AllApplications").
		// Flatten to []string to keep the JSON output compact.
		if t.Target != "" {
			out.Targets = append(out.Targets, t.Target)
		}
	}
	return out
}

func convertCrossTenantChannel(r *crossTenantAccessChannelRaw) types.CrossTenantAccessChannel {
	if r == nil {
		return types.CrossTenantAccessChannel{}
	}
	return types.CrossTenantAccessChannel{
		UsersAndGroups: convertCrossTenantTarget(r.UsersAndGroups),
		Applications:   convertCrossTenantTarget(r.Applications),
	}
}

func convertCrossTenantChannels(in, out *crossTenantAccessChannelRaw) types.CrossTenantPolicyChannels {
	return types.CrossTenantPolicyChannels{
		Inbound:  convertCrossTenantChannel(in),
		Outbound: convertCrossTenantChannel(out),
	}
}

func convertCrossTenantInboundTrust(r *crossTenantInboundTrustRaw) types.CrossTenantInboundTrust {
	out := types.CrossTenantInboundTrust{}
	if r == nil {
		return out
	}
	if r.IsMfaAccepted != nil {
		out.IsMfaAccepted = *r.IsMfaAccepted
	}
	if r.IsCompliantDeviceAccepted != nil {
		out.IsCompliantDeviceAccepted = *r.IsCompliantDeviceAccepted
	}
	if r.IsHybridAzureADJoinedDeviceAccepted != nil {
		out.IsHybridAzureADJoinedDeviceAccepted = *r.IsHybridAzureADJoinedDeviceAccepted
	}
	return out
}

func convertCrossTenantTenantRestrictions(r *crossTenantTenantRestrictionsRaw) types.CrossTenantTenantRestrictions {
	if r == nil {
		return types.CrossTenantTenantRestrictions{}
	}
	return types.CrossTenantTenantRestrictions{
		UsersAndGroups: convertCrossTenantTarget(r.UsersAndGroups),
		Applications:   convertCrossTenantTarget(r.Applications),
	}
}

// GetRoleManagementPolicies fetches PIM policies for role assignments
// Returns map of roleDefinitionId+scopeId -> policy settings
// Endpoint: GET /roleManagement/directory/roleManagementPolicyAssignments?$expand=policy($expand=rules)
func (c *Client) GetRoleManagementPolicies(ctx context.Context) (map[string]types.RolePIMPolicy, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if !c.connected {
		return nil, fmt.Errorf("not connected")
	}

	policyMap := make(map[string]types.RolePIMPolicy)

	// Call policy endpoint with expanded rules
	body, err := c.callGraphHTTP(ctx, "GET", "/roleManagement/directory/roleManagementPolicyAssignments?$expand=policy($expand=rules)", nil)
	if err != nil {
		// If endpoint fails (missing permissions or PIM not configured), return empty map
		// This allows audit to continue without policy enrichment
		return policyMap, nil
	}

	// Parse response
	var result struct {
		Value []struct {
			ID               string `json:"id"`
			RoleDefinitionID string `json:"roleDefinitionId"`
			ScopeID          string `json:"scopeId"`
			Policy           struct {
				Rules []struct {
					ID       string `json:"id"`
					RuleType string `json:"@odata.type"`
					Target   struct {
						Caller     string   `json:"caller"`
						Operations []string `json:"operations"`
						Level      string   `json:"level"`
					} `json:"target"`
					MaximumDuration         *string `json:"maximumDuration,omitempty"`
					IsApprovalRequired      *bool   `json:"isApprovalRequired,omitempty"`
					IsJustificationRequired *bool   `json:"isJustificationRequired,omitempty"`
				} `json:"rules"`
			} `json:"policy"`
		} `json:"value"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		return policyMap, nil
	}

	// Build policy map
	for _, assignment := range result.Value {
		if assignment.RoleDefinitionID == "" {
			continue
		}

		key := assignment.RoleDefinitionID + "|" + assignment.ScopeID
		policy := types.RolePIMPolicy{
			RoleDefinitionID: assignment.RoleDefinitionID,
			ScopeID:          assignment.ScopeID,
		}

		// Extract relevant rules for EndUser activation
		for _, rule := range assignment.Policy.Rules {
			if rule.Target.Caller != "EndUser" {
				continue
			}
			isActivationRule := false
			for _, op := range rule.Target.Operations {
				if op == "All" || op == "Activate" {
					isActivationRule = true
					break
				}
			}
			if !isActivationRule {
				continue
			}

			switch {
			case strings.Contains(rule.RuleType, "Approval"):
				if rule.IsApprovalRequired != nil {
					policy.RequiresApproval = rule.IsApprovalRequired
				}
			case strings.Contains(rule.RuleType, "Expiration"):
				if rule.MaximumDuration != nil {
					policy.MaximumDuration = *rule.MaximumDuration
				}
			case strings.Contains(rule.RuleType, "Enablement"):
				if rule.IsJustificationRequired != nil {
					policy.RequiresJustification = rule.IsJustificationRequired
				}
			}
		}

		policyMap[key] = policy
	}

	return policyMap, nil
}

// enrichGroupsWithExternalMembers adds external (guest) member counts to groups
// This makes N API calls (one per group) so it's done concurrently after the main group fetch
// Requires GroupMember.Read.All permission
func (c *Client) enrichGroupsWithExternalMembers(ctx context.Context, groups []types.Group) {
	// Process groups concurrently to minimize latency impact
	// Using a semaphore to limit concurrent requests
	semaphore := make(chan struct{}, 10) // Max 10 concurrent requests
	var wg sync.WaitGroup

	for i := range groups {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			semaphore <- struct{}{}        // Acquire
			defer func() { <-semaphore }() // Release

			groupID := groups[idx].ObjectSID
			if groupID == "" {
				return
			}

			// Call /groups/{id}/members/$count?$filter=userType eq 'Guest'
			// Requires ConsistencyLevel: eventual header
			endpoint := fmt.Sprintf("/groups/%s/members/$count?$filter=userType eq 'Guest'", groupID)
			headers := map[string]string{
				"ConsistencyLevel": "eventual",
			}

			body, err := c.callGraphHTTP(ctx, "GET", endpoint, headers)
			if err != nil {
				// Silently ignore errors - this is best-effort enrichment
				return
			}

			// Response is just a plain integer (not JSON)
			countStr := strings.TrimSpace(string(body))
			count, err := strconv.Atoi(countStr)
			if err == nil {
				groups[idx].AzureExternalMembersCount = &count
			}
			// Silently ignore parsing errors
		}(i)
	}

	wg.Wait()
}

// enrichGroupsWithMembers fetches direct member IDs for each group via
// /groups/{id}/members?$select=id and populates group.Members.
func (c *Client) enrichGroupsWithMembers(ctx context.Context, grps []types.Group) {
	semaphore := make(chan struct{}, 10)
	var wg sync.WaitGroup

	for i := range grps {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			groupID := grps[idx].ObjectSID
			if groupID == "" {
				return
			}

			var memberIDs []string
			nextLink := fmt.Sprintf("/groups/%s/members?$select=id&$top=999", groupID)

			for nextLink != "" {
				body, err := c.callGraphHTTP(ctx, "GET", nextLink, nil)
				if err != nil {
					return
				}
				var page struct {
					Value []struct {
						ID string `json:"id"`
					} `json:"value"`
					NextLink string `json:"@odata.nextLink"`
				}
				if json.Unmarshal(body, &page) != nil {
					return
				}
				for _, m := range page.Value {
					if m.ID != "" {
						memberIDs = append(memberIDs, m.ID)
					}
				}
				if page.NextLink != "" {
					nextLink = strings.TrimPrefix(page.NextLink, "https://graph.microsoft.com/v1.0")
				} else {
					nextLink = ""
				}
			}

			grps[idx].Members = memberIDs
			grps[idx].Member = memberIDs
		}(i)
	}

	wg.Wait()
}

// GetGroups retrieves groups from Azure AD with pagination support
func (c *Client) GetGroups(ctx context.Context, opts providers.QueryOptions) ([]types.Group, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if !c.connected || c.graphClient == nil {
		return nil, fmt.Errorf("not connected")
	}

	var azureGroups []types.Group

	// Build query - limit page size to 999 (Graph API max per page)
	pageSize := 999
	if opts.MaxResults > 0 && opts.MaxResults < 999 {
		pageSize = opts.MaxResults
	}

	requestConfig := &groups.GroupsRequestBuilderGetRequestConfiguration{
		QueryParameters: &groups.GroupsRequestBuilderGetQueryParameters{
			Select: []string{
				"id",
				"displayName",
				"description",
				"groupTypes",
				"securityEnabled",
				"mailEnabled",
				"membershipRule",
				"membershipRuleProcessingState",
				"isAssignableToRole",
				"visibility",
				"createdDateTime",
				"onPremisesSyncEnabled", // Hybrid sync status
				"members",
			},
			Top: int32Ptr(int32(pageSize)),
		},
	}

	if opts.Filter != "" {
		requestConfig.QueryParameters.Filter = &opts.Filter
	}

	// Pagination loop - follow @odata.nextLink until exhausted or limit reached
	var nextLink *string
	requestBuilder := c.graphClient.Groups()

	for {
		var result models.GroupCollectionResponseable
		var err error

		// Use WithUrl for subsequent pages, normal Get for first page
		if nextLink != nil && *nextLink != "" {
			result, err = requestBuilder.WithUrl(*nextLink).Get(ctx, nil)
		} else {
			result, err = requestBuilder.Get(ctx, requestConfig)
		}

		if err != nil {
			return nil, providers.NewProviderError(providers.ProviderTypeAzure, "get groups", err)
		}

		// Process current page
		for _, g := range result.GetValue() {
			group := convertAzureGroup(g)
			azureGroups = append(azureGroups, group)

			// Stop if we've reached the requested limit
			if opts.MaxResults > 0 && len(azureGroups) >= opts.MaxResults {
				return azureGroups, nil
			}
		}

		// Check for next page
		nextLink = result.GetOdataNextLink()
		if nextLink == nil || *nextLink == "" {
			break // No more pages
		}
	}

	// Enrich groups with external (guest) member counts
	c.enrichGroupsWithExternalMembers(ctx, azureGroups)

	// Enrich groups with member IDs (for the Assets → Groups → Detail page)
	c.enrichGroupsWithMembers(ctx, azureGroups)

	return azureGroups, nil
}

// GetComputers retrieves devices from Azure AD (computers in Azure AD context)
func (c *Client) GetComputers(ctx context.Context, opts providers.QueryOptions) ([]types.Computer, error) {
	// Azure AD uses "devices" instead of computers
	// This requires Device.Read.All permission
	c.mu.RLock()
	defer c.mu.RUnlock()

	if !c.connected || c.graphClient == nil {
		return nil, fmt.Errorf("not connected")
	}

	// Get devices via raw request (msgraph-sdk-go device support varies)
	// For now, return empty - device enumeration requires additional setup
	return []types.Computer{}, nil
}

// GetDomainInfo retrieves tenant/domain information
func (c *Client) GetDomainInfo(ctx context.Context) (*types.DomainInfo, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if !c.connected || c.graphClient == nil {
		return nil, fmt.Errorf("not connected")
	}

	// Get organization info
	org, err := c.graphClient.Organization().Get(ctx, nil)
	if err != nil {
		return nil, providers.NewProviderError(providers.ProviderTypeAzure, "get organization", err)
	}

	info := &types.DomainInfo{}

	if orgs := org.GetValue(); len(orgs) > 0 {
		o := orgs[0]
		if id := o.GetId(); id != nil {
			info.DomainSID = *id // Use tenant ID as "SID"
		}
		if name := o.GetDisplayName(); name != nil {
			info.DomainName = *name
		}

		// Get verified domains
		if domains := o.GetVerifiedDomains(); len(domains) > 0 {
			for _, d := range domains {
				if d.GetIsDefault() != nil && *d.GetIsDefault() {
					if name := d.GetName(); name != nil {
						info.ForestName = *name
					}
				}
			}
		}
	}

	return info, nil
}

// === Azure Provider methods (Entra ID security audit) ===

// GetConditionalAccessPolicies retrieves all Conditional Access policies
func (c *Client) GetConditionalAccessPolicies(ctx context.Context) ([]types.ConditionalAccessPolicy, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if !c.connected || c.graphClient == nil {
		return nil, fmt.Errorf("not connected")
	}

	result, err := c.graphClient.Identity().ConditionalAccess().Policies().Get(ctx, nil)
	if err != nil {
		return nil, providers.NewProviderError(providers.ProviderTypeAzure, "get conditional access policies", err)
	}

	var policies []types.ConditionalAccessPolicy
	for _, p := range result.GetValue() {
		policy := convertConditionalAccessPolicy(p)
		policies = append(policies, policy)
	}
	return policies, nil
}

// GetConditionalAccessPoliciesDetail returns the full nested Microsoft Graph
// shape for every Conditional Access policy. Unlike GetConditionalAccessPolicies
// (which goes through the SDK and produces a flat type used by in-collector
// detectors), this call hits /identity/conditionalAccess/policies via raw HTTP
// and unmarshals into ConditionalAccessPolicyDetail to preserve every field
// the SDK doesn't surface yet (tokenProtection.isEnabled, signInFrequency
// .isEnabled, persistentBrowser.isEnabled, applicationEnforcedRestrictions,
// continuousAccessEvaluation, secureSignInSession, disableResilienceDefaults,
// authenticationStrength, authenticationFlows, includeUserActions, ...).
//
// Best-effort: a 403/404 from the Graph (missing Policy.Read.All scope or
// tenant where CA isn't licensed) returns (nil, nil) so the audit continues
// — the engine layer logs an AZURE_CA_POLICIES_FAILED warning when the call
// errors. /identity/conditionalAccess/policies returns the full set in one
// page (no @odata.nextLink documented), so we don't paginate.
func (c *Client) GetConditionalAccessPoliciesDetail(ctx context.Context) ([]types.ConditionalAccessPolicyDetail, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if !c.connected {
		return nil, fmt.Errorf("not connected")
	}

	body, err := c.callGraphHTTP(ctx, "GET", "/identity/conditionalAccess/policies", nil)
	if err != nil {
		return nil, err
	}
	var page struct {
		Value []types.ConditionalAccessPolicyDetail `json:"value"`
	}
	if jerr := json.Unmarshal(body, &page); jerr != nil {
		return nil, jerr
	}
	return page.Value, nil
}

// GetDirectoryRoles retrieves directory role definitions with enabled status
func (c *Client) GetDirectoryRoles(ctx context.Context) ([]types.DirectoryRole, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if !c.connected || c.graphClient == nil {
		return nil, fmt.Errorf("not connected")
	}

	result, err := c.graphClient.DirectoryRoles().Get(ctx, nil)
	if err != nil {
		return nil, providers.NewProviderError(providers.ProviderTypeAzure, "get directory roles", err)
	}

	var roles []types.DirectoryRole
	for _, r := range result.GetValue() {
		role := types.DirectoryRole{
			IsEnabled: true, // Active directory roles are enabled by definition
		}
		if id := r.GetId(); id != nil {
			role.ID = *id
		}
		if name := r.GetDisplayName(); name != nil {
			role.DisplayName = *name
		}
		if desc := r.GetDescription(); desc != nil {
			role.Description = *desc
		}
		if tmplID := r.GetRoleTemplateId(); tmplID != nil {
			role.RoleTemplateID = *tmplID
		}
		role.IsBuiltIn = true // directoryRoles are always built-in
		roles = append(roles, role)
	}
	return roles, nil
}

// GetRoleAssignments retrieves all directory role assignments (active + eligible).
//
// /roleManagement/directory/roleAssignments rejects a request that expands
// more than one navigation property — "Only one property can be expanded in
// a single query" — confirmed live against a real tenant on 2026-08-26
// (B_156/T_058). This is a constraint of THIS endpoint specifically: the
// sibling PIM endpoints this package also calls (roleEligibilityScheduleInstances,
// roleAssignmentSchedules, roleAssignmentScheduleRequests) all accept
// $expand=principal,roleDefinition together without complaint. The previous
// code expanded both principal and roleDefinition (each with a nested
// $select) in one call, which Graph has always rejected with HTTP 400 — an
// error silently swallowed by the caller in engine.go (B_157), so this had
// never been noticed. Two paginated passes, merged by assignment id.
func (c *Client) GetRoleAssignments(ctx context.Context) ([]types.RoleAssignment, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if !c.connected || c.graphClient == nil {
		return nil, fmt.Errorf("not connected")
	}

	// Get PIM-eligible roles via HTTP direct (SDK doesn't fully support PIM)
	eligibilityMap, _ := c.GetRoleEligibilitySchedules(ctx)

	// Get PIM policies for role activation requirements
	policyMap, _ := c.GetRoleManagementPolicies(ctx)

	base, err := c.getRoleAssignmentsWithPrincipal(ctx)
	if err != nil {
		return nil, providers.NewProviderError(providers.ProviderTypeAzure, "get role assignments", err)
	}
	roleNames, err := c.getRoleAssignmentRoleNames(ctx)
	if err != nil {
		return nil, providers.NewProviderError(providers.ProviderTypeAzure, "get role assignments (role names)", err)
	}

	// Build map of active assignments for easy lookup
	activeMap := make(map[string]types.RoleAssignment)
	for _, a := range base {
		a.RoleName = roleNames[a.ID]

		// Create composite key for matching with eligible assignments
		key := a.PrincipalID + "|" + a.RoleID + "|" + a.DirectoryScopeID

		// Check if this active assignment also has eligibility (PIM-activated)
		if eligible, exists := eligibilityMap[key]; exists {
			a.AssignmentType = "activated"
			a.IsEligible = true
			a.IsPermanent = false
			a.MemberType = eligible.MemberType
			delete(eligibilityMap, key)
		} else {
			a.AssignmentType = "direct"
			a.IsPermanent = true
			a.IsEligible = false
			a.MemberType = "direct"
		}

		// Enrich with PIM policy settings (if available)
		policyKey := a.RoleID + "|" + a.DirectoryScopeID
		if policy, exists := policyMap[policyKey]; exists {
			if policy.RequiresJustification != nil {
				a.RequiresJustification = *policy.RequiresJustification
			}
			if policy.RequiresApproval != nil {
				a.RequiresApproval = *policy.RequiresApproval
			}
			if policy.MaximumDuration != "" {
				a.ActivationDuration = policy.MaximumDuration
			}
		}

		activeMap[key] = a
	}

	return mergeRoleAssignments(activeMap, eligibilityMap, policyMap), nil
}

// getRoleAssignmentsWithPrincipal fetches the base assignment fields plus the
// full principal object ($expand=principal, no nested $select needed — the
// default expansion already carries id/displayName/userPrincipalName/mail/
// jobTitle/department for a user principal). Paginated: this tenant-wide
// endpoint has no built-in cap.
func (c *Client) getRoleAssignmentsWithPrincipal(ctx context.Context) ([]types.RoleAssignment, error) {
	endpoint := "/roleManagement/directory/roleAssignments?$expand=principal&$top=999"
	var out []types.RoleAssignment
	for endpoint != "" {
		body, err := c.callGraphHTTP(ctx, "GET", endpoint, nil)
		if err != nil {
			return nil, err
		}
		var page struct {
			Value []struct {
				ID               string `json:"id"`
				PrincipalID      string `json:"principalId"`
				RoleDefinitionID string `json:"roleDefinitionId"`
				DirectoryScopeID string `json:"directoryScopeId"`
				Principal        struct {
					DisplayName       string `json:"displayName"`
					UserPrincipalName string `json:"userPrincipalName"`
					Mail              string `json:"mail"`
					JobTitle          string `json:"jobTitle"`
					Department        string `json:"department"`
					OdataType         string `json:"@odata.type"`
				} `json:"principal"`
			} `json:"value"`
			NextLink string `json:"@odata.nextLink"`
		}
		if err := json.Unmarshal(body, &page); err != nil {
			return nil, err
		}
		for _, ra := range page.Value {
			a := types.RoleAssignment{
				ID:                  ra.ID,
				PrincipalID:         ra.PrincipalID,
				RoleID:              ra.RoleDefinitionID,
				DirectoryScopeID:    ra.DirectoryScopeID,
				PrincipalName:       ra.Principal.DisplayName,
				UserPrincipalName:   ra.Principal.UserPrincipalName,
				Mail:                ra.Principal.Mail,
				PrincipalJobTitle:   ra.Principal.JobTitle,
				PrincipalDepartment: ra.Principal.Department,
			}
			switch {
			case strings.Contains(ra.Principal.OdataType, "user"):
				a.PrincipalType = "User"
			case strings.Contains(ra.Principal.OdataType, "group"):
				a.PrincipalType = "Group"
			case strings.Contains(ra.Principal.OdataType, "servicePrincipal"):
				a.PrincipalType = "ServicePrincipal"
			}
			out = append(out, a)
		}
		endpoint = c.nextRoleAssignmentsPage(page.NextLink)
	}
	return out, nil
}

// getRoleAssignmentRoleNames fetches roleDefinitionId -> displayName, keyed
// by assignment id ($expand=roleDefinition, the other half of the split
// forced by the single-expand constraint documented on GetRoleAssignments).
func (c *Client) getRoleAssignmentRoleNames(ctx context.Context) (map[string]string, error) {
	endpoint := "/roleManagement/directory/roleAssignments?$expand=roleDefinition($select=id,displayName)&$top=999"
	names := make(map[string]string)
	for endpoint != "" {
		body, err := c.callGraphHTTP(ctx, "GET", endpoint, nil)
		if err != nil {
			return nil, err
		}
		var page struct {
			Value []struct {
				ID             string `json:"id"`
				RoleDefinition struct {
					DisplayName string `json:"displayName"`
				} `json:"roleDefinition"`
			} `json:"value"`
			NextLink string `json:"@odata.nextLink"`
		}
		if err := json.Unmarshal(body, &page); err != nil {
			return nil, err
		}
		for _, ra := range page.Value {
			names[ra.ID] = ra.RoleDefinition.DisplayName
		}
		endpoint = c.nextRoleAssignmentsPage(page.NextLink)
	}
	return names, nil
}

// nextRoleAssignmentsPage trims an @odata.nextLink down to the relative
// endpoint callGraphHTTP expects, against either the real Graph host or a
// test's graphBaseURL override. Returns "" when there is no next page or the
// link's host isn't recognised (stop rather than mis-route).
func (c *Client) nextRoleAssignmentsPage(nextLink string) string {
	if nextLink == "" {
		return ""
	}
	if next := strings.TrimPrefix(nextLink, "https://graph.microsoft.com/v1.0"); next != nextLink {
		return next
	}
	if c.graphBaseURL != "" {
		if next := strings.TrimPrefix(nextLink, c.graphBaseURL+"v1.0"); next != nextLink {
			return next
		}
	}
	return "" // unrecognised host — stop pagination
}

// mergeRoleAssignments collects active-map and eligible-only entries into one
// deterministically ordered slice, enriching eligible-only entries with PIM
// policy settings along the way. Extracted out of GetRoleAssignments as a
// pure function so the ordering can be unit tested without a live Graph
// connection.
//
// Sorted by ID (T_046/B_048/T_049): activeMap and eligibilityMap are maps, so
// ranging them directly gives a randomized order per process — same tenant,
// different JSON, different sha256 across runs. Every detector that consumes
// AzureRoleAssignments (PIM, privileged-access/roles, membership) trusts this
// slice's order as-is; this is the single point that makes that order
// deterministic for all of them at once.
func mergeRoleAssignments(activeMap, eligibilityMap map[string]types.RoleAssignment, policyMap map[string]types.RolePIMPolicy) []types.RoleAssignment {
	var assignments []types.RoleAssignment

	for _, a := range activeMap {
		assignments = append(assignments, a)
	}

	for _, eligible := range eligibilityMap {
		policyKey := eligible.RoleID + "|" + eligible.DirectoryScopeID
		if policy, exists := policyMap[policyKey]; exists {
			if policy.RequiresJustification != nil {
				eligible.RequiresJustification = *policy.RequiresJustification
			}
			if policy.RequiresApproval != nil {
				eligible.RequiresApproval = *policy.RequiresApproval
			}
			if policy.MaximumDuration != "" {
				eligible.ActivationDuration = policy.MaximumDuration
			}
		}
		assignments = append(assignments, eligible)
	}

	sort.Slice(assignments, func(i, j int) bool { return assignments[i].ID < assignments[j].ID })
	return assignments
}

// sortedSetKeys returns the keys of a string-set map (bool values used only
// for membership) in sorted order.
//
// Sorted (T_046/B_048/T_049): a string-set map ranged directly gives a
// randomized order per process — same app, different JSON, different sha256
// across runs. Used by enrichAppRegistrations for AppRegistration.ApiPermissions;
// extracted as a pure function so the ordering can be unit tested directly.
func sortedSetKeys(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// GetAppRegistrations retrieves all application registrations with pagination support
func (c *Client) GetAppRegistrations(ctx context.Context, opts providers.QueryOptions) ([]types.AppRegistration, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if !c.connected || c.graphClient == nil {
		return nil, fmt.Errorf("not connected")
	}

	var apps []types.AppRegistration

	// Build query - limit page size to 999 (Graph API max per page)
	pageSize := 999
	if opts.MaxResults > 0 && opts.MaxResults < 999 {
		pageSize = opts.MaxResults
	}

	requestConfig := &applications.ApplicationsRequestBuilderGetRequestConfiguration{
		QueryParameters: &applications.ApplicationsRequestBuilderGetQueryParameters{
			Top: int32Ptr(int32(pageSize)),
		},
	}

	// Pagination loop - follow @odata.nextLink until exhausted or limit reached
	var nextLink *string
	requestBuilder := c.graphClient.Applications()

	for {
		var result models.ApplicationCollectionResponseable
		var err error

		// Use WithUrl for subsequent pages, normal Get for first page
		if nextLink != nil && *nextLink != "" {
			result, err = requestBuilder.WithUrl(*nextLink).Get(ctx, nil)
		} else {
			result, err = requestBuilder.Get(ctx, requestConfig)
		}

		if err != nil {
			return nil, providers.NewProviderError(providers.ProviderTypeAzure, "get app registrations", err)
		}

		// Process current page
		for _, a := range result.GetValue() {
			app := convertAppRegistration(a)
			apps = append(apps, app)

			// Stop if we've reached the requested limit
			if opts.MaxResults > 0 && len(apps) >= opts.MaxResults {
				break
			}
		}

		if opts.MaxResults > 0 && len(apps) >= opts.MaxResults {
			break
		}

		// Check for next page
		nextLink = result.GetOdataNextLink()
		if nextLink == nil || *nextLink == "" {
			break // No more pages
		}
	}

	// Enrich apps with owner names and permission names concurrently
	c.enrichAppRegistrations(ctx, apps)

	return apps, nil
}

// enrichAppRegistrations fetches owners and resolves permission names for all apps.
// Done concurrently with a semaphore to limit parallelism.
func (c *Client) enrichAppRegistrations(ctx context.Context, apps []types.AppRegistration) {
	semaphore := make(chan struct{}, 10)
	var wg sync.WaitGroup

	for i := range apps {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			appID := apps[idx].ID
			if appID == "" {
				return
			}

			// Fetch owners
			body, err := c.callGraphHTTP(ctx, "GET",
				fmt.Sprintf("/applications/%s/owners?$select=id,displayName,userPrincipalName", appID), nil)
			if err == nil {
				var ownersResp struct {
					Value []struct {
						DisplayName       string `json:"displayName"`
						UserPrincipalName string `json:"userPrincipalName"`
					} `json:"value"`
				}
				if json.Unmarshal(body, &ownersResp) == nil {
					for _, o := range ownersResp.Value {
						if o.DisplayName != "" {
							apps[idx].Owners = append(apps[idx].Owners, o.DisplayName)
						}
						if o.UserPrincipalName != "" {
							apps[idx].OwnerUpns = append(apps[idx].OwnerUpns, o.UserPrincipalName)
						}
					}
				}
			}

			// Resolve permission GUIDs to human-readable names from the app manifest
			permSet := make(map[string]bool)
			for _, rra := range apps[idx].RequiredResourceAccess {
				for _, perm := range rra.Permissions {
					if perm.Name != "" {
						permSet[perm.Name] = true
					} else if name, ok := types.GraphPermissionNames[perm.ID]; ok {
						permSet[name] = true
					}
				}
			}

			// Fetch consented delegated permissions via the enterprise app (SP)
			// This catches permissions granted after app registration (admin consent).
			grantsBody, err := c.callGraphHTTP(ctx, "GET",
				fmt.Sprintf("/servicePrincipals(appId='%s')/oauth2PermissionGrants", apps[idx].AppID), nil)
			if err == nil {
				var grantsResp struct {
					Value []struct {
						Scope string `json:"scope"`
					} `json:"value"`
				}
				if json.Unmarshal(grantsBody, &grantsResp) == nil {
					for _, g := range grantsResp.Value {
						for _, scope := range strings.Split(g.Scope, " ") {
							scope = strings.TrimSpace(scope)
							if scope != "" {
								permSet[scope] = true
							}
						}
					}
				}
			}

			apps[idx].ApiPermissions = sortedSetKeys(permSet)
		}(i)
	}

	wg.Wait()
}

// GetServicePrincipals retrieves all service principals with pagination support
func (c *Client) GetServicePrincipals(ctx context.Context, opts providers.QueryOptions) ([]types.ServicePrincipal, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if !c.connected || c.graphClient == nil {
		return nil, fmt.Errorf("not connected")
	}

	var sps []types.ServicePrincipal

	// Build query - limit page size to 999 (Graph API max per page)
	pageSize := 999
	if opts.MaxResults > 0 && opts.MaxResults < 999 {
		pageSize = opts.MaxResults
	}

	requestConfig := &serviceprincipals.ServicePrincipalsRequestBuilderGetRequestConfiguration{
		QueryParameters: &serviceprincipals.ServicePrincipalsRequestBuilderGetQueryParameters{
			Top: int32Ptr(int32(pageSize)),
		},
	}

	// Pagination loop - follow @odata.nextLink until exhausted or limit reached
	var nextLink *string
	requestBuilder := c.graphClient.ServicePrincipals()

	for {
		var result models.ServicePrincipalCollectionResponseable
		var err error

		// Use WithUrl for subsequent pages, normal Get for first page
		if nextLink != nil && *nextLink != "" {
			result, err = requestBuilder.WithUrl(*nextLink).Get(ctx, nil)
		} else {
			result, err = requestBuilder.Get(ctx, requestConfig)
		}

		if err != nil {
			return nil, providers.NewProviderError(providers.ProviderTypeAzure, "get service principals", err)
		}

		// Process current page
		for _, sp := range result.GetValue() {
			principal := convertServicePrincipal(sp)
			sps = append(sps, principal)

			// Stop if we've reached the requested limit
			if opts.MaxResults > 0 && len(sps) >= opts.MaxResults {
				return sps, nil
			}
		}

		// Check for next page
		nextLink = result.GetOdataNextLink()
		if nextLink == nil || *nextLink == "" {
			break // No more pages
		}
	}

	// Enrich SPs with owners and signInActivity
	c.enrichServicePrincipals(ctx, sps)

	return sps, nil
}

// enrichServicePrincipals fetches owners and signInActivity for each SP concurrently.
func (c *Client) enrichServicePrincipals(ctx context.Context, sps []types.ServicePrincipal) {
	semaphore := make(chan struct{}, 10)
	var wg sync.WaitGroup

	for i := range sps {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			spID := sps[idx].ID
			if spID == "" {
				return
			}

			// Fetch owners
			body, err := c.callGraphHTTP(ctx, "GET",
				fmt.Sprintf("/servicePrincipals/%s/owners?$select=id,displayName,userPrincipalName", spID), nil)
			if err == nil {
				var ownersResp struct {
					Value []struct {
						DisplayName       string `json:"displayName"`
						UserPrincipalName string `json:"userPrincipalName"`
					} `json:"value"`
				}
				if json.Unmarshal(body, &ownersResp) == nil {
					for _, o := range ownersResp.Value {
						if o.DisplayName != "" {
							sps[idx].Owners = append(sps[idx].Owners, o.DisplayName)
						}
						if o.UserPrincipalName != "" {
							sps[idx].OwnerUpns = append(sps[idx].OwnerUpns, o.UserPrincipalName)
						}
					}
				}
			}

			// Fetch signInActivity + createdDateTime (requires AuditLog.Read.All).
			// createdDateTime is added in v3.1.30 §3 — the SDK doesn't expose it
			// on ServicePrincipalable so we pull it via HTTP $select alongside
			// signInActivity (single round-trip).
			body, err = c.callGraphHTTP(ctx, "GET",
				fmt.Sprintf("/servicePrincipals/%s?$select=id,signInActivity,createdDateTime", spID), nil)
			if err == nil {
				var spResp struct {
					CreatedDateTime string `json:"createdDateTime"`
					SignInActivity  *struct {
						LastSignInDateTime string `json:"lastSignInDateTime"`
					} `json:"signInActivity"`
				}
				if json.Unmarshal(body, &spResp) == nil {
					if spResp.SignInActivity != nil {
						if t, err := time.Parse(time.RFC3339, spResp.SignInActivity.LastSignInDateTime); err == nil {
							sps[idx].LastSignInDateTime = &t
						}
					}
					if spResp.CreatedDateTime != "" {
						if t, err := time.Parse(time.RFC3339, spResp.CreatedDateTime); err == nil {
							sps[idx].CreatedDateTime = &t
						}
					}
				}
			}

			// v3.1.30 §3 — fetch admin-consented application permissions
			// (appRoleAssignments). Distinct from oauth2PermissionGrants
			// (delegated consent) — these are tenant-wide application
			// permissions like Mail.Read or Directory.ReadWrite.All.
			if assignments, arErr := c.getSPAppRoleAssignments(ctx, spID); arErr == nil && len(assignments) > 0 {
				sps[idx].AppRoleAssignments = assignments
			}
		}(i)
	}

	wg.Wait()
}

// getSPAppRoleAssignments fetches /servicePrincipals/{spID}/appRoleAssignments
// (admin-consented app permissions). Resolves AppRoleID → human name via
// types.GraphPermissionNames and flags IsDangerous against
// types.DangerousGraphPermissions.
//
// Per-SP call — invoked from enrichServicePrincipals in the existing 10-way
// goroutine pool, so this scales the same as the owners/signInActivity
// enrichment (~1 batch of N per second on small tenants).
func (c *Client) getSPAppRoleAssignments(ctx context.Context, spID string) ([]types.AppRoleAssignment, error) {
	endpoint := fmt.Sprintf("/servicePrincipals/%s/appRoleAssignments?$top=999", spID)
	var out []types.AppRoleAssignment
	for endpoint != "" {
		body, err := c.callGraphHTTP(ctx, "GET", endpoint, nil)
		if err != nil {
			return out, err
		}
		var page struct {
			Value []struct {
				ID                   string `json:"id"`
				PrincipalID          string `json:"principalId"`
				PrincipalDisplayName string `json:"principalDisplayName"`
				PrincipalType        string `json:"principalType"`
				ResourceID           string `json:"resourceId"`
				ResourceDisplayName  string `json:"resourceDisplayName"`
				AppRoleID            string `json:"appRoleId"`
				CreatedDateTime      string `json:"createdDateTime"`
			} `json:"value"`
			NextLink string `json:"@odata.nextLink"`
		}
		if jerr := json.Unmarshal(body, &page); jerr != nil {
			return out, jerr
		}
		for _, a := range page.Value {
			ar := types.AppRoleAssignment{
				ID:                   a.ID,
				PrincipalID:          a.PrincipalID,
				PrincipalDisplayName: a.PrincipalDisplayName,
				PrincipalType:        a.PrincipalType,
				ResourceID:           a.ResourceID,
				ResourceDisplayName:  a.ResourceDisplayName,
				AppRoleID:            a.AppRoleID,
				CreatedDateTime:      a.CreatedDateTime,
			}
			// Resolve permission name from GUID via the existing catalog.
			if name, ok := types.GraphPermissionNames[a.AppRoleID]; ok {
				ar.AppRoleName = name
				if _, dang := types.DangerousGraphPermissions[name]; dang {
					ar.IsDangerous = true
				}
			}
			out = append(out, ar)
		}
		// Paginate. Graph returns absolute URLs in @odata.nextLink — pass
		// them through unchanged; callGraphHTTP handles both absolute and
		// relative paths.
		if page.NextLink != "" {
			// Strip the v1.0 prefix so callGraphHTTP can re-prepend it.
			endpoint = strings.TrimPrefix(page.NextLink, "https://graph.microsoft.com/v1.0")
			if endpoint == page.NextLink {
				// Couldn't strip — pagination URL points elsewhere; bail.
				break
			}
		} else {
			endpoint = ""
		}
	}
	return out, nil
}

// GetOAuth2PermissionGrants retrieves all OAuth2 permission grants (delegated consents)
func (c *Client) GetOAuth2PermissionGrants(ctx context.Context) ([]types.OAuth2PermissionGrant, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if !c.connected || c.graphClient == nil {
		return nil, fmt.Errorf("not connected")
	}

	result, err := c.graphClient.Oauth2PermissionGrants().Get(ctx, nil)
	if err != nil {
		return nil, providers.NewProviderError(providers.ProviderTypeAzure, "get oauth2 permission grants", err)
	}

	var grants []types.OAuth2PermissionGrant
	for _, g := range result.GetValue() {
		grant := types.OAuth2PermissionGrant{}
		if id := g.GetId(); id != nil {
			grant.ID = *id
		}
		if cid := g.GetClientId(); cid != nil {
			grant.ClientID = *cid
		}
		if ct := g.GetConsentType(); ct != nil {
			grant.ConsentType = *ct
		}
		if pid := g.GetPrincipalId(); pid != nil {
			grant.PrincipalID = *pid
		}
		if rid := g.GetResourceId(); rid != nil {
			grant.ResourceID = *rid
		}
		if scope := g.GetScope(); scope != nil {
			grant.Scope = *scope
		}
		// Note: ExpiryTime is not exposed in the msgraph-sdk-go model for OAuth2PermissionGrant
		grants = append(grants, grant)
	}
	return grants, nil
}

// GetAuthMethodsPolicy retrieves the authentication methods policy via raw
// HTTP — v3.1.30 §6 expanded the per-method shape (includeTargets/excludeTargets,
// FIDO2 attestation, MS Authenticator number-matching, etc.) and the SDK
// polymorphic getters were too brittle to extend cleanly.
//
// Backward compat: the AuthMethodsPolicy + AuthMethodConfig types stay
// strictly additive — the 5 existing detectors keep reading .State unchanged.
func (c *Client) GetAuthMethodsPolicy(ctx context.Context) (*types.AuthMethodsPolicy, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if !c.connected {
		return nil, fmt.Errorf("not connected")
	}
	body, err := c.callGraphHTTP(ctx, "GET", "/policies/authenticationMethodsPolicy", nil)
	if err != nil {
		return nil, providers.NewProviderError(providers.ProviderTypeAzure, "get auth methods policy", err)
	}
	var raw struct {
		RegistrationEnforcement *struct {
			AuthenticationMethodsRegistrationCampaign *struct {
				State string `json:"state"`
			} `json:"authenticationMethodsRegistrationCampaign"`
		} `json:"registrationEnforcement"`
		Configurations []json.RawMessage `json:"authenticationMethodConfigurations"`
	}
	if jerr := json.Unmarshal(body, &raw); jerr != nil {
		return nil, fmt.Errorf("decode auth methods policy: %w", jerr)
	}

	policy := &types.AuthMethodsPolicy{}
	if raw.RegistrationEnforcement != nil &&
		raw.RegistrationEnforcement.AuthenticationMethodsRegistrationCampaign != nil &&
		strings.EqualFold(raw.RegistrationEnforcement.AuthenticationMethodsRegistrationCampaign.State, "enabled") {
		policy.RegistrationEnforcement = true
	}

	// Each configuration is polymorphic — switch on `id` (Graph returns
	// canonical PascalCase: Fido2, MicrosoftAuthenticator, Sms, …).
	// We use the `id` rather than `@odata.type` because the id stays stable
	// even when Microsoft tweaks the @odata.type FQN.
	for _, rawCfg := range raw.Configurations {
		var head struct {
			ID    string `json:"id"`
			State string `json:"state"`
		}
		if json.Unmarshal(rawCfg, &head) != nil {
			continue
		}
		mc := types.AuthMethodConfig{State: head.State}
		mc.IncludeTargets, mc.ExcludeTargets = decodeAuthMethodTargets(rawCfg)

		switch head.ID {
		case "Fido2":
			mc.FIDO2 = decodeFIDO2Config(rawCfg)
			policy.FIDO2 = mc
		case "MicrosoftAuthenticator":
			mc.Authenticator = decodeAuthenticatorConfig(rawCfg)
			policy.MicrosoftAuthenticator = mc
		case "Sms":
			mc.SMSConfig = decodeSMSConfig(rawCfg)
			policy.SMS = mc
		case "Voice":
			mc.VoiceConfig = decodeVoiceConfig(rawCfg)
			policy.PhoneVoice = mc
		case "Email":
			policy.Email = mc
		case "TemporaryAccessPass":
			policy.TemporaryAccessPass = mc
		case "SoftwareOath":
			policy.SoftwareOath = mc
		case "HardwareOath":
			policy.HardwareOath = mc
		case "X509Certificate":
			policy.X509Certificate = mc
		case "QRCodePin":
			policy.QRCodePin = mc
		}
	}
	return policy, nil
}

func decodeAuthMethodTargets(raw json.RawMessage) (include, exclude []types.AuthMethodTarget) {
	var t struct {
		IncludeTargets []struct {
			TargetType             string `json:"targetType"`
			ID                     string `json:"id"`
			IsRegistrationRequired bool   `json:"isRegistrationRequired"`
		} `json:"includeTargets"`
		ExcludeTargets []struct {
			TargetType string `json:"targetType"`
			ID         string `json:"id"`
		} `json:"excludeTargets"`
	}
	if json.Unmarshal(raw, &t) != nil {
		return nil, nil
	}
	for _, x := range t.IncludeTargets {
		include = append(include, types.AuthMethodTarget{
			TargetType:             x.TargetType,
			ID:                     x.ID,
			IsRegistrationRequired: x.IsRegistrationRequired,
		})
	}
	for _, x := range t.ExcludeTargets {
		exclude = append(exclude, types.AuthMethodTarget{TargetType: x.TargetType, ID: x.ID})
	}
	return
}

func decodeFIDO2Config(raw json.RawMessage) *types.AuthMethodFIDO2Config {
	var f struct {
		IsAttestationEnforced            *bool `json:"isAttestationEnforced"`
		IsSelfServiceRegistrationAllowed *bool `json:"isSelfServiceRegistrationAllowed"`
		KeyRestrictions                  *struct {
			IsEnforced      *bool    `json:"isEnforced"`
			EnforcementType string   `json:"enforcementType"`
			AAGuids         []string `json:"aaGuids"`
		} `json:"keyRestrictions"`
	}
	if json.Unmarshal(raw, &f) != nil {
		return nil
	}
	out := &types.AuthMethodFIDO2Config{}
	if f.IsAttestationEnforced != nil {
		out.IsAttestationEnforced = *f.IsAttestationEnforced
	}
	if f.IsSelfServiceRegistrationAllowed != nil {
		out.IsSelfServiceRegistrationAllowed = *f.IsSelfServiceRegistrationAllowed
	}
	if f.KeyRestrictions != nil {
		kr := &types.AuthMethodKeyRestrictions{
			EnforcementType: f.KeyRestrictions.EnforcementType,
			AAGuids:         f.KeyRestrictions.AAGuids,
		}
		if f.KeyRestrictions.IsEnforced != nil {
			kr.IsEnforced = *f.KeyRestrictions.IsEnforced
		}
		out.KeyRestrictions = kr
	}
	return out
}

func decodeAuthenticatorConfig(raw json.RawMessage) *types.AuthMethodAuthenticatorConfig {
	var a struct {
		FeatureSettings *struct {
			NumberMatchingRequiredState *struct {
				State string `json:"state"`
			} `json:"numberMatchingRequiredState"`
			DisplayAppInformationRequiredState *struct {
				State string `json:"state"`
			} `json:"displayAppInformationRequiredState"`
			DisplayLocationInformationRequiredState *struct {
				State string `json:"state"`
			} `json:"displayLocationInformationRequiredState"`
		} `json:"featureSettings"`
	}
	if json.Unmarshal(raw, &a) != nil || a.FeatureSettings == nil {
		return nil
	}
	out := &types.AuthMethodAuthenticatorConfig{}
	if a.FeatureSettings.NumberMatchingRequiredState != nil {
		out.NumberMatchingRequiredState = a.FeatureSettings.NumberMatchingRequiredState.State
	}
	if a.FeatureSettings.DisplayAppInformationRequiredState != nil {
		out.DisplayAppInformationRequiredState = a.FeatureSettings.DisplayAppInformationRequiredState.State
	}
	if a.FeatureSettings.DisplayLocationInformationRequiredState != nil {
		out.DisplayLocationInformationRequiredState = a.FeatureSettings.DisplayLocationInformationRequiredState.State
	}
	return out
}

func decodeSMSConfig(raw json.RawMessage) *types.AuthMethodSMSConfig {
	var s struct {
		IsUsableForSignIn *bool `json:"isUsableForSignIn"`
	}
	if json.Unmarshal(raw, &s) != nil || s.IsUsableForSignIn == nil {
		return nil
	}
	return &types.AuthMethodSMSConfig{IsUsableForSignIn: *s.IsUsableForSignIn}
}

func decodeVoiceConfig(raw json.RawMessage) *types.AuthMethodVoiceConfig {
	var v struct {
		IsOfficePhoneAllowed *bool `json:"isOfficePhoneAllowed"`
	}
	if json.Unmarshal(raw, &v) != nil || v.IsOfficePhoneAllowed == nil {
		return nil
	}
	return &types.AuthMethodVoiceConfig{IsOfficePhoneAllowed: *v.IsOfficePhoneAllowed}
}

// GetAuthenticationStrengthPolicies fetches all built-in + custom strength
// policies from /policies/authenticationStrengthPolicies. Best-effort: 403
// (no P1/P2) returns nil + nil so the audit continues.
func (c *Client) GetAuthenticationStrengthPolicies(ctx context.Context) ([]types.AuthStrengthPolicy, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if !c.connected {
		return nil, fmt.Errorf("not connected")
	}
	// Graph rejects $top on this endpoint with "Query option 'Top' is not
	// allowed". The result set is small (~5-20 policies including built-ins)
	// so we don't need pagination control anyway.
	body, err := c.callGraphHTTP(ctx, "GET", "/policies/authenticationStrengthPolicies", nil)
	if err != nil {
		return nil, nil
	}
	var page struct {
		Value []struct {
			ID                    string   `json:"id"`
			DisplayName           string   `json:"displayName"`
			Description           string   `json:"description"`
			PolicyType            string   `json:"policyType"`
			RequirementsSatisfied string   `json:"requirementsSatisfied"`
			AllowedCombinations   []string `json:"allowedCombinations"`
		} `json:"value"`
	}
	if jerr := json.Unmarshal(body, &page); jerr != nil {
		return nil, nil
	}
	out := make([]types.AuthStrengthPolicy, 0, len(page.Value))
	for _, p := range page.Value {
		out = append(out, types.AuthStrengthPolicy{
			ID:                    p.ID,
			DisplayName:           p.DisplayName,
			Description:           p.Description,
			PolicyType:            p.PolicyType,
			RequirementsSatisfied: p.RequirementsSatisfied,
			AllowedCombinations:   p.AllowedCombinations,
		})
	}
	return out, nil
}

// GetUserRegistrationDetails fetches per-user registration details from
// /reports/authenticationMethods/userRegistrationDetails. Paginated. Returns
// the raw slice for the audit helper to aggregate (the per-user shape stays
// internal; only the aggregated stats reach the JSON output to keep the
// payload bounded on 10k-user tenants).
func (c *Client) GetUserRegistrationDetails(ctx context.Context) ([]types.UserRegistrationDetail, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if !c.connected {
		return nil, fmt.Errorf("not connected")
	}

	endpoint := "/reports/authenticationMethods/userRegistrationDetails?$top=999"
	var out []types.UserRegistrationDetail
	for endpoint != "" {
		body, err := c.callGraphHTTP(ctx, "GET", endpoint, nil)
		if err != nil {
			return out, nil
		}
		var page struct {
			Value []struct {
				ID                    string   `json:"id"`
				UserPrincipalName     string   `json:"userPrincipalName"`
				UserDisplayName       string   `json:"userDisplayName"`
				UserType              string   `json:"userType"`
				IsAdmin               bool     `json:"isAdmin"`
				IsMfaCapable          bool     `json:"isMfaCapable"`
				IsMfaRegistered       bool     `json:"isMfaRegistered"`
				IsPasswordlessCapable bool     `json:"isPasswordlessCapable"`
				IsSsprCapable         bool     `json:"isSsprCapable"`
				IsSsprEnabled         bool     `json:"isSsprEnabled"`
				IsSsprRegistered      bool     `json:"isSsprRegistered"`
				MethodsRegistered     []string `json:"methodsRegistered"`
				LastUpdatedDateTime   string   `json:"lastUpdatedDateTime"`
			} `json:"value"`
			NextLink string `json:"@odata.nextLink"`
		}
		if jerr := json.Unmarshal(body, &page); jerr != nil {
			return out, nil
		}
		for _, u := range page.Value {
			out = append(out, types.UserRegistrationDetail{
				UserID:                u.ID,
				UserPrincipalName:     u.UserPrincipalName,
				UserDisplayName:       u.UserDisplayName,
				UserType:              u.UserType,
				IsAdmin:               u.IsAdmin,
				IsMFACapable:          u.IsMfaCapable,
				IsMFARegistered:       u.IsMfaRegistered,
				IsPasswordlessCapable: u.IsPasswordlessCapable,
				IsSSPRCapable:         u.IsSsprCapable,
				IsSSPREnabled:         u.IsSsprEnabled,
				IsSSPRRegistered:      u.IsSsprRegistered,
				MethodsRegistered:     u.MethodsRegistered,
				LastUpdatedDateTime:   u.LastUpdatedDateTime,
			})
		}
		if page.NextLink != "" {
			endpoint = strings.TrimPrefix(page.NextLink, "https://graph.microsoft.com/v1.0")
			if endpoint == page.NextLink {
				break
			}
		} else {
			endpoint = ""
		}
	}
	return out, nil
}

// GetNamedLocations retrieves all named locations (IP-based and country-based)
func (c *Client) GetNamedLocations(ctx context.Context) ([]types.NamedLocation, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if !c.connected || c.graphClient == nil {
		return nil, fmt.Errorf("not connected")
	}

	result, err := c.graphClient.Identity().ConditionalAccess().NamedLocations().Get(ctx, nil)
	if err != nil {
		return nil, providers.NewProviderError(providers.ProviderTypeAzure, "get named locations", err)
	}

	var locations []types.NamedLocation
	for _, loc := range result.GetValue() {
		nl := types.NamedLocation{}
		if id := loc.GetId(); id != nil {
			nl.ID = *id
		}
		if name := loc.GetDisplayName(); name != nil {
			nl.DisplayName = *name
		}

		// Check if it's an IP-based named location
		if ipLoc, ok := loc.(*models.IpNamedLocation); ok {
			if trusted := ipLoc.GetIsTrusted(); trusted != nil {
				nl.IsTrusted = *trusted
			}
			for _, r := range ipLoc.GetIpRanges() {
				if cidr, ok := r.(*models.IPv4CidrRange); ok {
					if addr := cidr.GetCidrAddress(); addr != nil {
						nl.IPRanges = append(nl.IPRanges, *addr)
					}
				}
				if cidr, ok := r.(*models.IPv6CidrRange); ok {
					if addr := cidr.GetCidrAddress(); addr != nil {
						nl.IPRanges = append(nl.IPRanges, *addr)
					}
				}
			}
		}

		// Check if it's a country-based named location
		if countryLoc, ok := loc.(*models.CountryNamedLocation); ok {
			nl.CountriesAndRegions = countryLoc.GetCountriesAndRegions()
			if incUnknown := countryLoc.GetIncludeUnknownCountriesAndRegions(); incUnknown != nil {
				nl.IncludeUnknownCountriesAndRegions = *incUnknown
			}
		}

		locations = append(locations, nl)
	}
	return locations, nil
}

// GetRiskyUsers retrieves risky users from Identity Protection (requires P2 license)
func (c *Client) GetRiskyUsers(ctx context.Context) ([]types.RiskyUser, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if !c.connected || c.graphClient == nil {
		return nil, fmt.Errorf("not connected")
	}

	result, err := c.graphClient.IdentityProtection().RiskyUsers().Get(ctx, nil)
	if err != nil {
		return nil, providers.NewProviderError(providers.ProviderTypeAzure, "get risky users", err)
	}

	var riskyUsers []types.RiskyUser
	for _, ru := range result.GetValue() {
		user := types.RiskyUser{}
		if id := ru.GetId(); id != nil {
			user.ID = *id
		}
		if upn := ru.GetUserPrincipalName(); upn != nil {
			user.UserPrincipalName = *upn
		}
		if name := ru.GetUserDisplayName(); name != nil {
			user.UserDisplayName = *name
		}
		if level := ru.GetRiskLevel(); level != nil {
			user.RiskLevel = level.String()
		}
		if state := ru.GetRiskState(); state != nil {
			user.RiskState = state.String()
		}
		if detail := ru.GetRiskDetail(); detail != nil {
			user.RiskDetail = detail.String()
		}
		if updated := ru.GetRiskLastUpdatedDateTime(); updated != nil {
			user.RiskLastUpdated = *updated
		}
		riskyUsers = append(riskyUsers, user)
	}
	return riskyUsers, nil
}

// GetRiskySignIns retrieves risk detections from Identity Protection (requires P2 license)
func (c *Client) GetRiskySignIns(ctx context.Context) ([]types.RiskySignIn, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if !c.connected || c.graphClient == nil {
		return nil, fmt.Errorf("not connected")
	}

	result, err := c.graphClient.IdentityProtection().RiskDetections().Get(ctx, nil)
	if err != nil {
		return nil, providers.NewProviderError(providers.ProviderTypeAzure, "get risky sign-ins", err)
	}

	var riskySignIns []types.RiskySignIn
	for _, rd := range result.GetValue() {
		si := types.RiskySignIn{}
		if id := rd.GetId(); id != nil {
			si.ID = *id
		}
		if upn := rd.GetUserPrincipalName(); upn != nil {
			si.UserPrincipalName = *upn
		}
		if name := rd.GetUserDisplayName(); name != nil {
			si.UserDisplayName = *name
		}
		if level := rd.GetRiskLevel(); level != nil {
			si.RiskLevel = level.String()
		}
		if state := rd.GetRiskState(); state != nil {
			si.RiskState = state.String()
		}
		if detail := rd.GetRiskDetail(); detail != nil {
			si.RiskDetail = detail.String()
		}
		if detected := rd.GetDetectedDateTime(); detected != nil {
			si.DetectedDateTime = *detected
		}
		if ip := rd.GetIpAddress(); ip != nil {
			si.IPAddress = *ip
		}
		if loc := rd.GetLocation(); loc != nil {
			var parts []string
			if city := loc.GetCity(); city != nil {
				parts = append(parts, *city)
			}
			if country := loc.GetCountryOrRegion(); country != nil {
				parts = append(parts, *country)
			}
			si.Location = strings.Join(parts, ", ")
		}
		riskySignIns = append(riskySignIns, si)
	}
	return riskySignIns, nil
}

// GetSignInLogs fetches sign-in events from /beta/auditLogs/signIns for the
// last `days` days (clamped to 30 by the engine — Graph itself enforces a
// 30-day retention for non-P1/P2 tenants). Walks @odata.nextLink until
// either the page count is exhausted or `maxResults` is reached.
//
// Returns:
//   - logs: collected events (may be shorter than total if maxResults hit)
//   - truncated: true when maxResults stopped pagination early
//   - oldest: timestamp of the oldest event in `logs` — gives the SaaS the
//     real lookback window (e.g. truncation may shrink 30d to 6h on a
//     high-volume tenant)
//   - err: only network/auth errors after retries; per-page decoding errors
//     return what was collected so far + the error
//
// The beta endpoint is required: riskEventTypes_v2, incomingTokenType, and
// resourceDisplayName are not exposed in /v1.0. $select narrows the payload
// to the ~25 fields the SaaS actually uses (cuts payload ~40%).
func (c *Client) GetSignInLogs(ctx context.Context, days, maxResults int) ([]types.SignInLog, bool, time.Time, error) {
	if days <= 0 {
		days = 30
	}
	if days > 30 {
		days = 30
	}

	since := time.Now().UTC().Add(-time.Duration(days) * 24 * time.Hour).Format(time.RFC3339)

	// $select is intentionally NOT used: Graph rejects several of the
	// fields we need (authenticationDetails, sessionLifetimePolicies,
	// appliedConditionalAccessPolicies, location, deviceDetail, status)
	// inside $select — they're only returned in the default projection.
	// Probed manually via curl to confirm: each of these in $select returns
	// {"error":{"code":"UnknownError","message":"Unsupported Query."}}.
	// Bandwidth is bounded by --azure-signin-logs-max instead.
	//
	// Graph defaults to interactiveUser only — we MUST query each event
	// type explicitly to get the full picture (the spec asks for interactive
	// + non-interactive + service principal + managed identity). Doing this
	// in 4 separate calls (vs one OR-filter) keeps the @odata.nextLink
	// pagination simple and gives us per-type visibility on what was
	// collected vs truncated.
	signInEventTypes := []string{"interactiveUser", "nonInteractiveUser", "servicePrincipal", "managedIdentity"}

	// v3.1.33 — parallelize the 4 event types. Each type's pagination is
	// independent (Graph honors $filter signInEventTypes/any per-call), so
	// running them sequentially wastes 75% of the wall-clock budget. Going
	// parallel gives ~4x throughput per minute of budget; on a 5 min budget
	// this turns "got 4 days of one type" into "got 16 days across 4 types".
	//
	// Trade-off: 4 concurrent Graph calls instead of 1. Graph's per-tenant
	// rate limits are well above 4 RPS for read endpoints; callGraphHTTPRaw
	// already honors 429 Retry-After with exponential backoff, so transient
	// throttling self-heals. maxResults becomes a soft cap (atomic counter
	// shared across goroutines) — acceptable overshoot of up to 4 pages
	// (~4000 events) which is negligible vs the 500k default cap.

	type typeResult struct {
		eventType string
		logs      []types.SignInLog
		oldest    time.Time
		err       error
	}

	results := make([]typeResult, len(signInEventTypes))
	var totalCollected atomic.Int64
	var capHit atomic.Bool
	var wg sync.WaitGroup

	for i, eventType := range signInEventTypes {
		wg.Add(1)
		go func(idx int, et string) {
			defer wg.Done()

			filter := fmt.Sprintf(
				"createdDateTime ge %s and signInEventTypes/any(t:t eq '%s')",
				since, et,
			)
			endpoint := "/auditLogs/signIns?$top=1000&$filter=" + url.QueryEscape(filter)

			// v3.1.32 — per-page diagnostic so an operator can see whether
			// pagination is converging. Per-type counters (the parallel
			// goroutines interleave on stderr but each line is self-contained
			// via the type=... prefix).
			var pagesForType, eventsForType int
			typeStart := time.Now()
			var typeLogs []types.SignInLog
			var typeOldest time.Time

			for endpoint != "" {
				if capHit.Load() {
					break
				}
				pageStart := time.Now()
				body, err := c.callGraphHTTPRaw(ctx, "beta", "GET", endpoint, nil)
				if err != nil {
					fmt.Fprintf(os.Stderr,
						"warning: GetSignInLogs aborted (%s): pagesCollected=%d eventsForType=%d elapsed=%s err=%v\n",
						et, pagesForType, eventsForType, time.Since(typeStart).Round(time.Second), err)
					results[idx] = typeResult{eventType: et, logs: typeLogs, oldest: typeOldest, err: fmt.Errorf("get signin logs (%s): %w", et, err)}
					return
				}
				var page struct {
					Value    []types.SignInLog `json:"value"`
					NextLink string            `json:"@odata.nextLink"`
				}
				if err := json.Unmarshal(body, &page); err != nil {
					results[idx] = typeResult{eventType: et, logs: typeLogs, oldest: typeOldest, err: fmt.Errorf("decode signin logs page (%s): %w", et, err)}
					return
				}
				pagesForType++
				eventsForType += len(page.Value)
				newCumulative := totalCollected.Add(int64(len(page.Value)))
				fmt.Fprintf(os.Stderr,
					"signInLogs: type=%s page=%d events=%d cumulativeForType=%d cumulativeAll=%d hasNext=%v pageDuration=%s\n",
					et, pagesForType, len(page.Value), eventsForType, newCumulative, page.NextLink != "", time.Since(pageStart).Round(time.Millisecond))

				for i := range page.Value {
					ev := page.Value[i]
					if typeOldest.IsZero() || ev.CreatedDateTime.Before(typeOldest) {
						typeOldest = ev.CreatedDateTime
					}
					typeLogs = append(typeLogs, ev)
				}

				if maxResults > 0 && newCumulative >= int64(maxResults) {
					if capHit.CompareAndSwap(false, true) {
						fmt.Fprintf(os.Stderr,
							"signInLogs: maxResults soft cap (%d) hit during %s page %d — signalling other goroutines to stop\n",
							maxResults, et, pagesForType)
					}
					break
				}
				endpoint = page.NextLink
			}
			fmt.Fprintf(os.Stderr,
				"signInLogs: type=%s done — pages=%d events=%d duration=%s\n",
				et, pagesForType, eventsForType, time.Since(typeStart).Round(time.Second))
			results[idx] = typeResult{eventType: et, logs: typeLogs, oldest: typeOldest, err: nil}
		}(i, eventType)
	}
	wg.Wait()

	// Merge with deduplication — a single event can carry multiple
	// signInEventTypes (e.g. interactiveUser AND nonInteractiveUser) and
	// would appear in two parallel queries; we dedup post-merge instead
	// of guarding a shared map during pagination.
	var (
		all      []types.SignInLog
		oldest   time.Time
		seen     = make(map[string]struct{})
		firstErr error
	)
	truncated := capHit.Load()
	for _, r := range results {
		if r.err != nil && firstErr == nil {
			firstErr = r.err
		}
		for _, ev := range r.logs {
			if _, dup := seen[ev.ID]; dup {
				continue
			}
			seen[ev.ID] = struct{}{}
			if oldest.IsZero() || ev.CreatedDateTime.Before(oldest) {
				oldest = ev.CreatedDateTime
			}
			all = append(all, ev)
		}
	}
	return all, truncated, oldest, firstErr
}

// GetDirectoryAudits fetches directory audit events from
// /v1.0/auditLogs/directoryAudits for the last `days` days, filtered to the
// 5 security-relevant categories. Walks @odata.nextLink until exhausted, the
// budget context cancels, or maxResults is reached.
//
// Mirrors the parallelization pattern of GetSignInLogs (v3.1.33): each of
// the 5 categories paginates in its own goroutine, then results are merged
// + de-duped by ID. Categories are independent calls because Graph rejects
// composite OR filters with $orderby on this endpoint, and per-category
// queries also let each goroutine make progress even if one category is
// throttled or missing data.
//
// Returns:
//   - events: collected directory audits (may be shorter than total if
//     maxResults or the budget context terminated pagination early)
//   - truncated: true when maxResults stopped pagination early (NOT when
//     ctx.Err() fires — caller distinguishes via ctx.Err())
//   - newest, oldest: bounding activityDateTime so the SaaS knows the
//     real lookback window
//   - err: only network/auth errors after retries; partial events still
//     returned alongside
func (c *Client) GetDirectoryAudits(ctx context.Context, days, maxResults int) ([]types.DirectoryAudit, bool, time.Time, time.Time, error) {
	if days <= 0 {
		days = 90
	}
	since := time.Now().UTC().Add(-time.Duration(days) * 24 * time.Hour).Format(time.RFC3339)

	// Tenants without P1/P2 license cap directory-audit retention well below
	// 90 days (typically ~30). Graph rejects an out-of-range $filter with a
	// 400 carrying the actual minimum date in the message:
	//   "Minimum allowed time for activityDateTime is 4/5/2026 12:00:00 AM"
	// We probe with the same $top=1000 the goroutines use — Graph is more
	// tolerant on $top=1 and won't surface the 400 there. Probing once before
	// fanning out lets all 5 categories share the clamped 'since' instead of
	// each goroutine retrying independently.
	probeFilter := fmt.Sprintf("activityDateTime ge %s and category eq 'UserManagement'", since)
	probeEndpoint := "/auditLogs/directoryAudits?$top=1000&$filter=" + url.QueryEscape(probeFilter)
	if _, perr := c.callGraphHTTPRaw(ctx, "v1.0", "GET", probeEndpoint, nil); perr != nil {
		if minTime, ok := parseGraphMinAllowedTime(perr.Error()); ok {
			fmt.Fprintf(os.Stderr,
				"directoryAudits: tenant retention shorter than %dd — clamping since from %s to %s (Graph minimum)\n",
				days, since, minTime.Format(time.RFC3339))
			// Add a 1-second margin to the minimum so equality edge cases pass.
			since = minTime.Add(1 * time.Second).UTC().Format(time.RFC3339)
		} else {
			fmt.Fprintf(os.Stderr,
				"directoryAudits: probe failed with un-parseable error (will let goroutines surface): %v\n", perr)
		}
	}

	categories := []string{
		"RoleManagement",
		"ConditionalAccess",
		"ApplicationManagement",
		"GroupManagement",
		"UserManagement",
	}

	type catResult struct {
		category string
		events   []types.DirectoryAudit
		err      error
	}

	results := make([]catResult, len(categories))
	var totalCollected atomic.Int64
	var capHit atomic.Bool
	var wg sync.WaitGroup

	for i, cat := range categories {
		wg.Add(1)
		go func(idx int, category string) {
			defer wg.Done()

			filter := fmt.Sprintf("activityDateTime ge %s and category eq '%s'", since, category)
			endpoint := "/auditLogs/directoryAudits?$top=1000&$filter=" + url.QueryEscape(filter)

			var pagesForCat, eventsForCat int
			catStart := time.Now()
			var catEvents []types.DirectoryAudit

			for endpoint != "" {
				if capHit.Load() {
					break
				}
				pageStart := time.Now()
				body, err := c.callGraphHTTPRaw(ctx, "v1.0", "GET", endpoint, nil)
				if err != nil {
					fmt.Fprintf(os.Stderr,
						"warning: GetDirectoryAudits aborted (%s): pagesCollected=%d eventsForCat=%d elapsed=%s err=%v\n",
						category, pagesForCat, eventsForCat, time.Since(catStart).Round(time.Second), err)
					results[idx] = catResult{category: category, events: catEvents, err: fmt.Errorf("get directory audits (%s): %w", category, err)}
					return
				}
				var page struct {
					Value    []types.DirectoryAudit `json:"value"`
					NextLink string                 `json:"@odata.nextLink"`
				}
				if err := json.Unmarshal(body, &page); err != nil {
					results[idx] = catResult{category: category, events: catEvents, err: fmt.Errorf("decode directory audits page (%s): %w", category, err)}
					return
				}
				pagesForCat++
				eventsForCat += len(page.Value)
				newCumulative := totalCollected.Add(int64(len(page.Value)))
				fmt.Fprintf(os.Stderr,
					"directoryAudits: cat=%s page=%d events=%d cumulativeForCat=%d cumulativeAll=%d hasNext=%v pageDuration=%s\n",
					category, pagesForCat, len(page.Value), eventsForCat, newCumulative, page.NextLink != "", time.Since(pageStart).Round(time.Millisecond))

				catEvents = append(catEvents, page.Value...)

				if maxResults > 0 && newCumulative >= int64(maxResults) {
					if capHit.CompareAndSwap(false, true) {
						fmt.Fprintf(os.Stderr,
							"directoryAudits: maxResults soft cap (%d) hit during %s page %d — signalling other goroutines to stop\n",
							maxResults, category, pagesForCat)
					}
					break
				}
				endpoint = page.NextLink
			}
			fmt.Fprintf(os.Stderr,
				"directoryAudits: cat=%s done — pages=%d events=%d duration=%s\n",
				category, pagesForCat, eventsForCat, time.Since(catStart).Round(time.Second))
			results[idx] = catResult{category: category, events: catEvents, err: nil}
		}(i, cat)
	}
	wg.Wait()

	// Merge with deduplication by ID (defensive — Graph shouldn't return the
	// same event under two categories but the API spec doesn't strictly
	// forbid it, e.g. cross-category role-assignment-on-an-app events).
	var (
		all      []types.DirectoryAudit
		newest   time.Time
		oldest   time.Time
		seen     = make(map[string]struct{})
		firstErr error
	)
	truncated := capHit.Load()
	for _, r := range results {
		if r.err != nil && firstErr == nil {
			firstErr = r.err
		}
		for _, ev := range r.events {
			if _, dup := seen[ev.ID]; dup {
				continue
			}
			seen[ev.ID] = struct{}{}
			if newest.IsZero() || ev.ActivityDateTime.After(newest) {
				newest = ev.ActivityDateTime
			}
			if oldest.IsZero() || ev.ActivityDateTime.Before(oldest) {
				oldest = ev.ActivityDateTime
			}
			all = append(all, ev)
		}
	}
	return all, truncated, newest, oldest, firstErr
}

// GetAuthorizationPolicy fetches /policies/authorizationPolicy. Single-shot
// call (no pagination, payload <2KB). Used by the v3.1.37 baseline security
// score for the user-consent / app-creation / tenant-creation / guest-invite
// gates.
//
// Best-effort: 403 ("Authorization_RequestDenied" — missing Policy.Read.All)
// or 404 (tenant without the policy materialised) returns nil, nil so the
// audit pipeline keeps going. The baseline checks that depend on the policy
// will surface as status="unknown" instead.
func (c *Client) GetAuthorizationPolicy(ctx context.Context) (*types.AuthorizationPolicy, error) {
	body, err := c.callGraphHTTP(ctx, "GET", "/policies/authorizationPolicy", nil)
	if err != nil {
		if strings.Contains(err.Error(), "403") || strings.Contains(err.Error(), "404") {
			return nil, nil
		}
		return nil, err
	}
	var p types.AuthorizationPolicy
	if err := json.Unmarshal(body, &p); err != nil {
		return nil, fmt.Errorf("decode authorizationPolicy: %w", err)
	}
	return &p, nil
}

// GetAdminConsentRequestPolicy fetches /policies/adminConsentRequestPolicy.
// Single-shot call. Used by the v3.1.37 baseline security score to verify
// the admin-consent workflow is enabled (so users hitting a permission gate
// route to admin review instead of being blocked silently).
//
// Same best-effort 403/404 handling as GetAuthorizationPolicy.
func (c *Client) GetAdminConsentRequestPolicy(ctx context.Context) (*types.AdminConsentRequestPolicy, error) {
	body, err := c.callGraphHTTP(ctx, "GET", "/policies/adminConsentRequestPolicy", nil)
	if err != nil {
		if strings.Contains(err.Error(), "403") || strings.Contains(err.Error(), "404") {
			return nil, nil
		}
		return nil, err
	}
	var p types.AdminConsentRequestPolicy
	if err := json.Unmarshal(body, &p); err != nil {
		return nil, fmt.Errorf("decode adminConsentRequestPolicy: %w", err)
	}
	return &p, nil
}

// GetEntraBackupStatus probes the Microsoft Graph endpoint for Entra Backup
// & Recovery (announced by Microsoft late 2025) and returns the tenant's
// backup configuration.
//
// As of v3.1.37 (May 2026) the Graph API for Entra Backup is NOT YET
// generally available — probing all 12 candidate paths returned HTTP 400
// "Resource not found for the segment 'backup'". This method is therefore
// designed as a forward-compatible probe: when Microsoft eventually GAs
// the API at /admin/backup/configuration (most likely path per Graph
// naming conventions), the next audit picks it up automatically with no
// rebuild needed.
//
// Returns a fully-populated EntraBackupStatus on every call:
//   - HTTP 200 → parses real configuration, Available=true
//   - HTTP 4xx → fallback object Available=false, Reason describes why
//   - Network error → fallback object Available=false, Reason="...network..."
//
// Never returns a hard error — the caller is meant to treat this as
// best-effort observability: the SaaS analyzer reads Available + Reason to
// distinguish "API not yet GA" (info) from "tenant has no backup
// configured" (critical) from "permission missing" (operator action).
func (c *Client) GetEntraBackupStatus(ctx context.Context, collectorVersion string) (*types.EntraBackupStatus, error) {
	probedAt := time.Now().UTC()
	body, err := c.callGraphHTTP(ctx, "GET", "/admin/backup/configuration", nil)
	if err != nil {
		return makeBackupFallback(err.Error(), probedAt, collectorVersion), nil
	}
	// Successful 200 — try to decode. The shape Microsoft will eventually
	// ship is unknown today; we use a best-effort raw map decode and pull
	// the fields we care about. If the shape doesn't match what we expect,
	// fall back gracefully (Available stays true if we got a 200, but
	// fields we couldn't parse stay zero-valued).
	var raw map[string]interface{}
	if jerr := json.Unmarshal(body, &raw); jerr != nil {
		return makeBackupFallback("response decode failed: "+jerr.Error(), probedAt, collectorVersion), nil
	}
	st := &types.EntraBackupStatus{
		Available:        true,
		ProbedAt:         probedAt,
		CollectorVersion: collectorVersion,
		RestorePoints:    []types.EntraBackupRestorePoint{},
	}
	if v, ok := raw["enabled"].(bool); ok {
		st.Enabled = v
	}
	if v, ok := raw["retentionDays"].(float64); ok {
		st.RetentionDays = int(v)
	}
	if v, ok := raw["frequency"].(string); ok {
		st.Frequency = v
	}
	if !st.Enabled {
		st.EstimatedRecoveryTime = "Unknown — backup not configured on this tenant"
	}
	return st, nil
}

// makeBackupFallback returns the standard "API not reachable" payload with
// a human-readable reason classified from the underlying error string. The
// shape is identical to the success case so the SaaS analyzer reads the
// same JSON keys whatever the verdict — it just checks Available + Reason.
func makeBackupFallback(errMsg string, probedAt time.Time, collectorVersion string) *types.EntraBackupStatus {
	reason := classifyBackupError(errMsg)
	return &types.EntraBackupStatus{
		Available:             false,
		Reason:                reason,
		Enabled:               false,
		Scope:                 types.EntraBackupScope{},
		RetentionDays:         0,
		RestorePoints:         []types.EntraBackupRestorePoint{},
		EstimatedRecoveryTime: "Unknown — Entra Backup API not yet available in this collector",
		ProbedAt:              probedAt,
		CollectorVersion:      collectorVersion,
	}
}

// classifyBackupError maps a callGraphHTTP error string to one of a small
// set of human-readable reasons. Useful so the SaaS UI can display
// different actionable hints based on whether the API is missing entirely
// (waiting on Microsoft) vs the customer has a permission gap.
func classifyBackupError(errMsg string) string {
	switch {
	case strings.Contains(errMsg, "400"):
		return "Microsoft Graph API for Entra Backup not yet generally available (HTTP 400 — segment 'backup' not found in Graph). This collector probed /admin/backup/configuration; when Microsoft GAs the API at this or another path, the next audit picks it up automatically."
	case strings.Contains(errMsg, "401"):
		return "Microsoft Graph endpoint requires authentication that wasn't accepted (HTTP 401). Verify the collector's app registration is consented in this tenant."
	case strings.Contains(errMsg, "403"):
		return "Permission BackupRestoreConfiguration.Read.All (or equivalent) not granted to the collector app registration (HTTP 403). Grant the permission and re-run the audit."
	case strings.Contains(errMsg, "404"):
		return "Entra Backup endpoint not found on this tenant (HTTP 404). The feature may be region-restricted or not available on this license tier."
	case strings.Contains(errMsg, "429") || strings.Contains(errMsg, "throttled"):
		return "Microsoft Graph throttled the probe (HTTP 429). Audit will retry on the next run."
	default:
		return "Entra Backup probe failed: " + errMsg
	}
}

// GetGroupTransitiveMembers expands a group's membership recursively (Graph
// pre-flattens nested groups for us — the response contains User /
// ServicePrincipal leaves and any Group entries that couldn't be resolved).
//
// Used by v3.1.37 §3 to count actual humans reachable through "All Cloud
// Admins"-style groups assigned to AI agent admin roles.
//
// Best-effort:
//   - HTTP 200 → parsed members (may be empty)
//   - HTTP 403 (missing Group.Read.All) → nil, false, nil (silent skip;
//     caller leaves expandedMembers empty in the payload, SaaS shows
//     "membership not visible — grant Group.Read.All")
//   - HTTP 404 (group deleted between collection and expansion) → nil, false, nil
//   - Other transport error → nil, false, err so the caller can attribute
//     a warning if it cares
//
// maxN soft-caps the merged list to avoid blowing up the audit JSON on
// 10k-member groups; truncated=true when we stopped pagination early. Pass
// 0 to disable the cap (not recommended).
func (c *Client) GetGroupTransitiveMembers(ctx context.Context, groupID string, maxN int) ([]types.GroupMember, bool, error) {
	if groupID == "" {
		return nil, false, fmt.Errorf("groupID is required")
	}
	endpoint := "/groups/" + url.PathEscape(groupID) +
		"/transitiveMembers?$select=id,displayName,userPrincipalName&$top=999"

	var (
		members   []types.GroupMember
		truncated bool
	)

	for endpoint != "" {
		body, err := c.callGraphHTTP(ctx, "GET", endpoint, nil)
		if err != nil {
			if strings.Contains(err.Error(), "403") || strings.Contains(err.Error(), "404") {
				return nil, false, nil
			}
			return members, truncated, fmt.Errorf("get transitive members for group %s: %w", groupID, err)
		}
		// Polymorphic decode: each entry carries an @odata.type that tells us
		// whether it's a #microsoft.graph.user / .group / .servicePrincipal.
		var page struct {
			Value []struct {
				ODataType         string `json:"@odata.type"`
				ID                string `json:"id"`
				DisplayName       string `json:"displayName"`
				UserPrincipalName string `json:"userPrincipalName,omitempty"`
			} `json:"value"`
			NextLink string `json:"@odata.nextLink"`
		}
		if jerr := json.Unmarshal(body, &page); jerr != nil {
			return members, truncated, fmt.Errorf("decode transitive members page: %w", jerr)
		}
		for _, m := range page.Value {
			members = append(members, types.GroupMember{
				ID:                m.ID,
				Type:              odataTypeToMemberType(m.ODataType),
				DisplayName:       m.DisplayName,
				UserPrincipalName: m.UserPrincipalName,
			})
			if maxN > 0 && len(members) >= maxN {
				truncated = true
				return members, truncated, nil
			}
		}
		// Graph's nextLink is the full URL; callGraphHTTP knows how to handle
		// either an absolute URL or a path, so we don't trim the prefix.
		endpoint = page.NextLink
	}
	return members, truncated, nil
}

// odataTypeToMemberType maps "#microsoft.graph.user" → "user", etc. Anything
// unrecognised falls back to "unknown" so the SaaS analyzer can surface the
// raw count without pretending it's a human.
func odataTypeToMemberType(odataType string) string {
	switch odataType {
	case "#microsoft.graph.user":
		return "user"
	case "#microsoft.graph.group":
		return "group"
	case "#microsoft.graph.servicePrincipal":
		return "servicePrincipal"
	default:
		return "unknown"
	}
}

// GetSecurityDefaults retrieves the security defaults policy
func (c *Client) GetSecurityDefaults(ctx context.Context) (*types.TenantSecurityDefaults, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if !c.connected || c.graphClient == nil {
		return nil, fmt.Errorf("not connected")
	}

	result, err := c.graphClient.Policies().IdentitySecurityDefaultsEnforcementPolicy().Get(ctx, nil)
	if err != nil {
		return nil, providers.NewProviderError(providers.ProviderTypeAzure, "get security defaults", err)
	}

	sd := &types.TenantSecurityDefaults{}
	if enabled := result.GetIsEnabled(); enabled != nil {
		sd.IsEnabled = *enabled
	}
	if name := result.GetDisplayName(); name != nil {
		sd.DisplayName = *name
	}
	return sd, nil
}

// GetTenantConfig retrieves tenant-wide configuration from multiple endpoints
func (c *Client) GetTenantConfig(ctx context.Context) (*types.AzureTenantConfig, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if !c.connected || c.graphClient == nil {
		return nil, fmt.Errorf("not connected")
	}

	cfg := &types.AzureTenantConfig{}

	// Fetch security defaults
	if sd, err := c.getSecurityDefaultsUnlocked(ctx); err == nil {
		cfg.SecurityDefaults = sd
	}

	// Fetch authorization policy for guest/consent settings
	authPolicies, err := c.graphClient.Policies().AuthorizationPolicy().Get(ctx, nil)
	if err == nil {
		if invite := authPolicies.GetAllowInvitesFrom(); invite != nil {
			cfg.GuestInvitationPolicy = invite.String()
		}
		if consent := authPolicies.GetDefaultUserRolePermissions(); consent != nil {
			if reg := consent.GetAllowedToCreateApps(); reg != nil {
				cfg.UserRegistrationAllowed = *reg
			}
		}
	}

	return cfg, nil
}

// getSecurityDefaultsUnlocked is an internal helper (caller must hold c.mu)
func (c *Client) getSecurityDefaultsUnlocked(ctx context.Context) (*types.TenantSecurityDefaults, error) {
	result, err := c.graphClient.Policies().IdentitySecurityDefaultsEnforcementPolicy().Get(ctx, nil)
	if err != nil {
		return nil, err
	}
	sd := &types.TenantSecurityDefaults{}
	if enabled := result.GetIsEnabled(); enabled != nil {
		sd.IsEnabled = *enabled
	}
	if name := result.GetDisplayName(); name != nil {
		sd.DisplayName = *name
	}
	return sd, nil
}

// GetSubscribedSkus returns the full list of subscribed SKUs on the tenant.
// v3.1.38 §1 — exposes the data that GetLicenseTier was already pulling from
// /subscribedSkus but discarding. The slice carries skuId, skuPartNumber,
// capabilityStatus, prepaidUnits/consumedUnits, and the embedded servicePlans
// list — enough for the SaaS License ROI matrix.
//
// Best-effort: 403 (missing Organization.Read.All) returns nil, nil so the
// audit pipeline keeps moving and the licenseInfo helper marks dependent
// fields with a Reason.
func (c *Client) GetSubscribedSkus(ctx context.Context) ([]types.SubscribedSku, error) {
	body, err := c.callGraphHTTP(ctx, "GET", "/subscribedSkus", nil)
	if err != nil {
		if strings.Contains(err.Error(), "403") || strings.Contains(err.Error(), "404") {
			return nil, nil
		}
		return nil, err
	}
	var resp struct {
		Value []struct {
			SkuID            string `json:"skuId"`
			SkuPartNumber    string `json:"skuPartNumber"`
			CapabilityStatus string `json:"capabilityStatus"`
			PrepaidUnits     struct {
				Enabled int `json:"enabled"`
			} `json:"prepaidUnits"`
			ConsumedUnits int `json:"consumedUnits"`
			ServicePlans  []struct {
				ServicePlanID      string `json:"servicePlanId"`
				ServicePlanName    string `json:"servicePlanName"`
				ProvisioningStatus string `json:"provisioningStatus"`
			} `json:"servicePlans"`
		} `json:"value"`
	}
	if jerr := json.Unmarshal(body, &resp); jerr != nil {
		return nil, fmt.Errorf("decode subscribedSkus: %w", jerr)
	}
	out := make([]types.SubscribedSku, 0, len(resp.Value))
	for _, s := range resp.Value {
		sku := types.SubscribedSku{
			SkuID:            s.SkuID,
			SkuPartNumber:    s.SkuPartNumber,
			CapabilityStatus: s.CapabilityStatus,
			PrepaidUnits:     s.PrepaidUnits.Enabled,
			ConsumedUnits:    s.ConsumedUnits,
		}
		sku.AvailableUnits = sku.PrepaidUnits - sku.ConsumedUnits
		if sku.AvailableUnits < 0 {
			sku.AvailableUnits = 0
		}
		for _, sp := range s.ServicePlans {
			sku.ServicePlans = append(sku.ServicePlans, types.SubscribedServicePlan{
				ServicePlanID:      sp.ServicePlanID,
				ServicePlanName:    sp.ServicePlanName,
				ProvisioningStatus: sp.ProvisioningStatus,
			})
		}
		out = append(out, sku)
	}
	return out, nil
}

// DeriveLicenseTier returns the Entra license tier (free|p1|p2) by walking
// a subscribed-SKU slice. Pure — no I/O. Pulled out of GetLicenseTier so
// the v3.1.38 §1 collectAzureData wiring can call /subscribedSkus once and
// reuse the result for both the legacy AzureLicenseTier string AND the
// new audit.licenseInfo payload.
func DeriveLicenseTier(skus []types.SubscribedSku) string {
	tier := "free"
	for _, sku := range skus {
		if sku.CapabilityStatus != "Enabled" {
			continue
		}
		pn := strings.ToUpper(sku.SkuPartNumber)
		switch {
		case strings.Contains(pn, "AAD_PREMIUM_P2") || strings.Contains(pn, "EMSPREMIUM") ||
			strings.Contains(pn, "SPE_E5") || strings.Contains(pn, "IDENTITY_THREAT_PROTECTION"):
			return "p2"
		case strings.Contains(pn, "AAD_PREMIUM") || strings.Contains(pn, "EMS") ||
			strings.Contains(pn, "SPE_E3") || strings.Contains(pn, "SPE_F1"):
			if tier != "p2" {
				tier = "p1"
			}
		}
	}
	return tier
}

// GetLicenseTier detects the Entra ID license tier (free, p1, p2). Backward
// compat wrapper: still callable as before; v3.1.38 §1 collectAzureData
// prefers GetSubscribedSkus + DeriveLicenseTier directly to avoid a duplicate
// /subscribedSkus call.
func (c *Client) GetLicenseTier(ctx context.Context) string {
	skus, err := c.GetSubscribedSkus(ctx)
	if err != nil {
		return ""
	}
	return DeriveLicenseTier(skus)
}

// GetAccessReviewDefinitionsCount returns the number of configured Access
// Review definitions on the tenant. v3.1.38 §1 — single-shot $count probe
// to detect "Access Reviews paid but not configured" dormancy.
//
// On 4xx (perm AccessReview.Read.All missing or feature unavailable in
// region) the error is propagated rather than silently swallowed — the
// caller MUST distinguish "endpoint inaccessible" (mark Reason, leave
// Dormant unset) from "endpoint probed and returned 0" (set Dormant when
// the tenant is licensed for the feature). A silent fallback would
// incorrectly mark the feature dormant on tenants where we just can't
// observe its state.
func (c *Client) GetAccessReviewDefinitionsCount(ctx context.Context) (int, error) {
	headers := map[string]string{"ConsistencyLevel": "eventual"}
	body, err := c.callGraphHTTP(ctx, "GET", "/identityGovernance/accessReviews/definitions?$count=true&$top=1", headers)
	if err != nil {
		return 0, err
	}
	var resp struct {
		Count int        `json:"@odata.count"`
		Value []struct{} `json:"value"`
	}
	if jerr := json.Unmarshal(body, &resp); jerr != nil {
		return 0, fmt.Errorf("decode accessReviews count: %w", jerr)
	}
	if resp.Count > 0 {
		return resp.Count, nil
	}
	return len(resp.Value), nil
}

// GetEntitlementAccessPackagesCount returns the number of configured access
// packages (Entitlement Management). v3.1.38 §1 — same error-propagating
// pattern as GetAccessReviewDefinitionsCount: a 4xx is surfaced so the
// caller can mark "endpoint inaccessible" instead of false-positive
// dormancy.
func (c *Client) GetEntitlementAccessPackagesCount(ctx context.Context) (int, error) {
	headers := map[string]string{"ConsistencyLevel": "eventual"}
	body, err := c.callGraphHTTP(ctx, "GET", "/identityGovernance/entitlementManagement/accessPackages?$count=true&$top=1", headers)
	if err != nil {
		return 0, err
	}
	var resp struct {
		Count int        `json:"@odata.count"`
		Value []struct{} `json:"value"`
	}
	if jerr := json.Unmarshal(body, &resp); jerr != nil {
		return 0, fmt.Errorf("decode entitlementManagement accessPackages count: %w", jerr)
	}
	if resp.Count > 0 {
		return resp.Count, nil
	}
	return len(resp.Value), nil
}

// GetVerifiedIDAuthoritiesCount returns the number of configured Verified ID
// authorities (issuers). v3.1.38 §1. The endpoint lives under /beta and
// many tenants still get HTTP 400 "segment not found" because the feature
// hasn't been provisioned in the region — error is surfaced so the caller
// can mark "endpoint inaccessible" with a clear Reason.
func (c *Client) GetVerifiedIDAuthoritiesCount(ctx context.Context) (int, error) {
	body, err := c.callGraphHTTPRaw(ctx, "beta", "GET", "/verifiableCredentials/authorities?$top=999", nil)
	if err != nil {
		return 0, err
	}
	var resp struct {
		Value []struct{} `json:"value"`
	}
	if jerr := json.Unmarshal(body, &resp); jerr != nil {
		return 0, fmt.Errorf("decode verifiableCredentials authorities: %w", jerr)
	}
	return len(resp.Value), nil
}

// GetOrganizationPrivacyStatementURL fetches /organization's privacyProfile.
// T_058 (B_158) — feeds AZ_NO_PRIVACY_STATEMENT, previously a hard-coded
// advisory. Returns "" (no error) when the tenant genuinely has no privacy
// statement configured (Graph omits privacyProfile entirely, or returns it
// with an empty statementUrl) — the caller distinguishes that from a failed
// probe via the returned error.
func (c *Client) GetOrganizationPrivacyStatementURL(ctx context.Context) (string, error) {
	body, err := c.callGraphHTTP(ctx, "GET", "/organization?$select=privacyProfile", nil)
	if err != nil {
		return "", err
	}
	var resp struct {
		Value []struct {
			PrivacyProfile *struct {
				StatementURL string `json:"statementUrl"`
			} `json:"privacyProfile"`
		} `json:"value"`
	}
	if jerr := json.Unmarshal(body, &resp); jerr != nil {
		return "", fmt.Errorf("decode organization privacyProfile: %w", jerr)
	}
	if len(resp.Value) == 0 || resp.Value[0].PrivacyProfile == nil {
		return "", nil
	}
	return resp.Value[0].PrivacyProfile.StatementURL, nil
}

// GetTermsOfUseAgreementsCount returns the number of configured Terms of Use
// agreements (/identityGovernance/termsOfUse/agreements). T_058 (B_158) —
// feeds AZ_NO_TERMS_OF_USE, previously a hard-coded advisory.
func (c *Client) GetTermsOfUseAgreementsCount(ctx context.Context) (int, error) {
	body, err := c.callGraphHTTP(ctx, "GET", "/identityGovernance/termsOfUse/agreements?$top=999", nil)
	if err != nil {
		return 0, err
	}
	var resp struct {
		Value []struct{} `json:"value"`
	}
	if jerr := json.Unmarshal(body, &resp); jerr != nil {
		return 0, fmt.Errorf("decode termsOfUse agreements: %w", jerr)
	}
	return len(resp.Value), nil
}

// GetDevices retrieves Entra-registered devices from /v1.0/devices with
// pagination. v3.1.38 §2 — feeds audit.hybridLinks.devices.
//
// trustType values:
//   - "AzureAd" : pure cloud-only Entra-joined device
//   - "ServerAd" : Hybrid Azure AD Joined (HAJ) — joined to both
//     on-prem AD and Entra. The actual hybrid bridge.
//   - "Workplace" : Workplace-joined (BYOD) — registered but not joined.
//
// Pagination via @odata.nextLink. maxN soft-caps the result to protect
// against runaway 100k+ device tenants; truncated=true when the cap was
// hit before exhaustion. Pass 0 to disable the cap (not recommended for
// production audits).
//
// Best-effort: 403 (Device.Read.All missing) returns (nil, false, nil).
// The caller marks the dependent fields with a Reason in the helper.
func (c *Client) GetDevices(ctx context.Context, maxN int) ([]types.AzureDevice, bool, error) {
	endpoint := "/devices?$select=id,deviceId,displayName,trustType,operatingSystem,onPremisesSyncEnabled,accountEnabled,approximateLastSignInDateTime&$top=999"
	var devices []types.AzureDevice
	truncated := false

	for endpoint != "" {
		body, err := c.callGraphHTTP(ctx, "GET", endpoint, nil)
		if err != nil {
			if strings.Contains(err.Error(), "403") || strings.Contains(err.Error(), "404") {
				return nil, false, nil
			}
			return devices, truncated, fmt.Errorf("get devices: %w", err)
		}
		var page struct {
			Value []struct {
				ID                            string  `json:"id"`
				DeviceID                      string  `json:"deviceId"`
				DisplayName                   string  `json:"displayName"`
				TrustType                     string  `json:"trustType"`
				OperatingSystem               string  `json:"operatingSystem"`
				OnPremisesSyncEnabled         *bool   `json:"onPremisesSyncEnabled"`
				AccountEnabled                *bool   `json:"accountEnabled"`
				ApproximateLastSignInDateTime *string `json:"approximateLastSignInDateTime"`
			} `json:"value"`
			NextLink string `json:"@odata.nextLink"`
		}
		if jerr := json.Unmarshal(body, &page); jerr != nil {
			return devices, truncated, fmt.Errorf("decode devices page: %w", jerr)
		}
		for _, d := range page.Value {
			device := types.AzureDevice{
				ID:                    d.ID,
				DeviceID:              d.DeviceID,
				DisplayName:           d.DisplayName,
				TrustType:             d.TrustType,
				OperatingSystem:       d.OperatingSystem,
				OnPremisesSyncEnabled: d.OnPremisesSyncEnabled,
				AccountEnabled:        d.AccountEnabled,
			}
			if d.ApproximateLastSignInDateTime != nil && *d.ApproximateLastSignInDateTime != "" {
				if t, perr := time.Parse(time.RFC3339, *d.ApproximateLastSignInDateTime); perr == nil {
					device.ApproximateLastSignIn = &t
				}
			}
			devices = append(devices, device)
			if maxN > 0 && len(devices) >= maxN {
				truncated = true
				return devices, truncated, nil
			}
		}
		endpoint = page.NextLink
	}
	return devices, truncated, nil
}

// === Conversion helpers for Azure types ===

// convertConditionalAccessPolicy converts a Graph CA policy to our type
func convertConditionalAccessPolicy(p models.ConditionalAccessPolicyable) types.ConditionalAccessPolicy {
	policy := types.ConditionalAccessPolicy{}
	if id := p.GetId(); id != nil {
		policy.ID = *id
	}
	if name := p.GetDisplayName(); name != nil {
		policy.DisplayName = *name
	}
	if state := p.GetState(); state != nil {
		policy.State = state.String()
	}
	if created := p.GetCreatedDateTime(); created != nil {
		policy.CreatedDateTime = *created
	}
	if modified := p.GetModifiedDateTime(); modified != nil {
		policy.ModifiedDateTime = *modified
	}

	// Conditions
	if cond := p.GetConditions(); cond != nil {
		// Users
		if u := cond.GetUsers(); u != nil {
			policy.IncludeUsers = u.GetIncludeUsers()
			policy.ExcludeUsers = u.GetExcludeUsers()
			policy.IncludeGroups = u.GetIncludeGroups()
			policy.ExcludeGroups = u.GetExcludeGroups()
			policy.IncludeRoles = u.GetIncludeRoles()
			policy.ExcludeRoles = u.GetExcludeRoles()
		}
		// Applications
		if apps := cond.GetApplications(); apps != nil {
			policy.IncludeApps = apps.GetIncludeApplications()
			policy.ExcludeApps = apps.GetExcludeApplications()
		}
		// Locations
		if loc := cond.GetLocations(); loc != nil {
			policy.IncludeLocations = loc.GetIncludeLocations()
			policy.ExcludeLocations = loc.GetExcludeLocations()
		}
		// Client app types
		if cats := cond.GetClientAppTypes(); cats != nil {
			for _, cat := range cats {
				policy.ClientAppTypes = append(policy.ClientAppTypes, cat.String())
			}
		}
		// Platforms
		if plat := cond.GetPlatforms(); plat != nil {
			if inc := plat.GetIncludePlatforms(); inc != nil {
				for _, p := range inc {
					policy.IncludePlatforms = append(policy.IncludePlatforms, p.String())
				}
			}
		}
		// Risk levels
		if risks := cond.GetUserRiskLevels(); risks != nil {
			for _, r := range risks {
				policy.UserRiskLevels = append(policy.UserRiskLevels, r.String())
			}
		}
		if risks := cond.GetSignInRiskLevels(); risks != nil {
			for _, r := range risks {
				policy.SignInRiskLevels = append(policy.SignInRiskLevels, r.String())
			}
		}
	}

	// Grant controls
	if gc := p.GetGrantControls(); gc != nil {
		if op := gc.GetOperator(); op != nil {
			policy.Operator = *op
		}
		for _, bc := range gc.GetBuiltInControls() {
			policy.GrantControls = append(policy.GrantControls, bc.String())
		}
	}

	// Session controls
	if sc := p.GetSessionControls(); sc != nil {
		if freq := sc.GetSignInFrequency(); freq != nil {
			if val := freq.GetValue(); val != nil {
				policy.SignInFrequencyValue = int(*val)
			}
			if ft := freq.GetTypeEscaped(); ft != nil {
				policy.SignInFrequencyType = ft.String()
			}
		}
		if pb := sc.GetPersistentBrowser(); pb != nil {
			if mode := pb.GetMode(); mode != nil {
				policy.PersistentBrowserMode = mode.String()
			}
		}
	}

	return policy
}

// convertAppRegistration converts a Graph application to our type
func convertAppRegistration(a models.Applicationable) types.AppRegistration {
	app := types.AppRegistration{}
	if id := a.GetId(); id != nil {
		app.ID = *id
	}
	if appID := a.GetAppId(); appID != nil {
		app.AppID = *appID
	}
	if name := a.GetDisplayName(); name != nil {
		app.DisplayName = *name
	}
	if created := a.GetCreatedDateTime(); created != nil {
		app.CreatedDateTime = *created
	}
	if audience := a.GetSignInAudience(); audience != nil {
		app.SignInAudience = *audience
	}

	// Required resource access (API permissions)
	for _, rra := range a.GetRequiredResourceAccess() {
		access := types.AppResourceAccess{}
		if resAppID := rra.GetResourceAppId(); resAppID != nil {
			access.ResourceAppID = *resAppID
		}
		for _, ra := range rra.GetResourceAccess() {
			perm := types.AppPermission{}
			if id := ra.GetId(); id != nil {
				perm.ID = id.String()
				// Resolve GUID to human-readable name
				if name, ok := types.GraphPermissionNames[perm.ID]; ok {
					perm.Name = name
				}
			}
			if t := ra.GetTypeEscaped(); t != nil {
				perm.Type = *t
			}
			access.Permissions = append(access.Permissions, perm)
		}
		app.RequiredResourceAccess = append(app.RequiredResourceAccess, access)
	}

	// Password credentials
	for _, pc := range a.GetPasswordCredentials() {
		cred := convertCredential(pc, "password")
		app.PasswordCredentials = append(app.PasswordCredentials, cred)
	}

	// Key credentials
	for _, kc := range a.GetKeyCredentials() {
		cred := convertKeyCredential(kc)
		app.KeyCredentials = append(app.KeyCredentials, cred)
	}

	// Publisher domain (for trust verification)
	if publisherDomain := a.GetPublisherDomain(); publisherDomain != nil {
		app.PublisherDomain = publisherDomain
	}

	// Reply URLs and web properties
	if web := a.GetWeb(); web != nil {
		app.ReplyURLs = web.GetRedirectUris()
		// Extract homepage URL
		if homepage := web.GetHomePageUrl(); homepage != nil {
			app.Homepage = homepage
		}
		// Extract logout URL
		if logoutUrl := web.GetLogoutUrl(); logoutUrl != nil {
			app.LogoutUrl = logoutUrl
		}
		// Check implicit grant
		if ig := web.GetImplicitGrantSettings(); ig != nil {
			if at := ig.GetEnableAccessTokenIssuance(); at != nil && *at {
				app.ImplicitGrantEnabled = true
			}
			if idt := ig.GetEnableIdTokenIssuance(); idt != nil && *idt {
				app.ImplicitGrantEnabled = true
			}
		}
	}

	return app
}

// convertServicePrincipal converts a Graph service principal to our type
func convertServicePrincipal(sp models.ServicePrincipalable) types.ServicePrincipal {
	principal := types.ServicePrincipal{}
	if id := sp.GetId(); id != nil {
		principal.ID = *id
	}
	if appID := sp.GetAppId(); appID != nil {
		principal.AppID = *appID
	}
	if name := sp.GetDisplayName(); name != nil {
		principal.DisplayName = *name
	}
	if spType := sp.GetServicePrincipalType(); spType != nil {
		principal.ServicePrincipalType = *spType
	}
	if enabled := sp.GetAccountEnabled(); enabled != nil {
		principal.AccountEnabled = *enabled
	}
	if orgID := sp.GetAppOwnerOrganizationId(); orgID != nil {
		principal.AppOwnerOrganizationID = orgID.String()
	}

	// Password credentials
	for _, pc := range sp.GetPasswordCredentials() {
		cred := convertCredential(pc, "password")
		principal.PasswordCredentials = append(principal.PasswordCredentials, cred)
	}

	// Key credentials
	for _, kc := range sp.GetKeyCredentials() {
		cred := convertKeyCredential(kc)
		principal.KeyCredentials = append(principal.KeyCredentials, cred)
	}

	// App role assignment required flag
	if appRoleAssignmentRequired := sp.GetAppRoleAssignmentRequired(); appRoleAssignmentRequired != nil {
		principal.AppRoleAssignmentRequired = appRoleAssignmentRequired
	}

	// v3.1.30 §3 — ConsentFix detection enrichments.
	// Note: CreatedDateTime is NOT exposed on ServicePrincipalable in this
	// SDK version (msgraph-sdk-go's SP model omits the inherited
	// DirectoryObject.createdDateTime getter). It's fetched separately via
	// HTTP $select in enrichServicePrincipals alongside signInActivity.
	if vp := sp.GetVerifiedPublisher(); vp != nil {
		out := &types.VerifiedPublisher{}
		if dn := vp.GetDisplayName(); dn != nil {
			out.DisplayName = *dn
		}
		if id := vp.GetVerifiedPublisherId(); id != nil {
			out.VerifiedPublisherID = *id
		}
		if added := vp.GetAddedDateTime(); added != nil {
			out.AddedDateTime = added.Format(time.RFC3339)
		}
		// Only attach when at least one field is populated — empty
		// VerifiedPublisher subobjects in the JSON output are noise.
		if out.DisplayName != "" || out.VerifiedPublisherID != "" || out.AddedDateTime != "" {
			principal.VerifiedPublisher = out
		}
	}
	if tags := sp.GetTags(); len(tags) > 0 {
		principal.Tags = append([]string(nil), tags...)
	}
	if audience := sp.GetSignInAudience(); audience != nil {
		principal.SignInAudience = *audience
	}

	return principal
}

// convertCredential converts a Graph password credential to our type
func convertCredential(pc models.PasswordCredentialable, credType string) types.AppCredential {
	cred := types.AppCredential{Type: credType}
	if kid := pc.GetKeyId(); kid != nil {
		cred.KeyID = kid.String()
	}
	if name := pc.GetDisplayName(); name != nil {
		cred.DisplayName = *name
	}
	if start := pc.GetStartDateTime(); start != nil {
		cred.StartDate = *start
	}
	if end := pc.GetEndDateTime(); end != nil {
		cred.EndDate = *end
	}
	return cred
}

// convertKeyCredential converts a Graph key credential to our type
func convertKeyCredential(kc models.KeyCredentialable) types.AppCredential {
	cred := types.AppCredential{Type: "certificate"}
	if kid := kc.GetKeyId(); kid != nil {
		cred.KeyID = kid.String()
	}
	if name := kc.GetDisplayName(); name != nil {
		cred.DisplayName = *name
	}
	if start := kc.GetStartDateTime(); start != nil {
		cred.StartDate = *start
	}
	if end := kc.GetEndDateTime(); end != nil {
		cred.EndDate = *end
	}
	if cki := kc.GetCustomKeyIdentifier(); len(cki) > 0 {
		cred.Thumbprint = fmt.Sprintf("%X", cki)
	}
	if usage := kc.GetUsage(); usage != nil {
		cred.Usage = *usage
	}
	return cred
}

// convertAzureUser converts an Azure AD user to our User type
func convertAzureUser(u models.Userable) types.User {
	user := types.User{}

	if id := u.GetId(); id != nil {
		user.ObjectSID = *id
	}
	if upn := u.GetUserPrincipalName(); upn != nil {
		user.UserPrincipalName = *upn
		user.SAMAccountName = extractSAMFromUPN(*upn)
	}
	if name := u.GetDisplayName(); name != nil {
		user.DisplayName = *name
	}
	if mail := u.GetMail(); mail != nil {
		user.Mail = *mail
	}
	if enabled := u.GetAccountEnabled(); enabled != nil {
		user.Disabled = !*enabled
		user.AzureAccountEnabled = enabled
	}
	if created := u.GetCreatedDateTime(); created != nil {
		user.Created = *created
		user.AzureCreatedDateTime = created
	}

	// Azure-specific fields
	if userType := u.GetUserType(); userType != nil {
		user.AzureUserType = userType
	}
	if jobTitle := u.GetJobTitle(); jobTitle != nil {
		user.AzureJobTitle = jobTitle
	}
	if officeLocation := u.GetOfficeLocation(); officeLocation != nil {
		user.AzureOfficeLocation = officeLocation
	}

	// Extract sign-in activity (both interactive and non-interactive)
	if signInActivity := u.GetSignInActivity(); signInActivity != nil {
		if lastSignIn := signInActivity.GetLastSignInDateTime(); lastSignIn != nil {
			user.AzureLastSignInDateTime = lastSignIn
		}
		if lastNonInteractive := signInActivity.GetLastNonInteractiveSignInDateTime(); lastNonInteractive != nil {
			user.AzureLastNonInteractiveSignInDateTime = lastNonInteractive
		}
	}

	// Extract usage location (for licensing compliance)
	if usageLocation := u.GetUsageLocation(); usageLocation != nil {
		user.AzureUsageLocation = usageLocation
	}

	// Extract proxy addresses (secondary email addresses)
	if proxyAddresses := u.GetProxyAddresses(); proxyAddresses != nil {
		user.AzureProxyAddresses = proxyAddresses
	}

	// Extract hybrid sync status
	if onPremisesSyncEnabled := u.GetOnPremisesSyncEnabled(); onPremisesSyncEnabled != nil {
		user.AzureOnPremisesSyncEnabled = onPremisesSyncEnabled
	}

	// v3.1.38 §2 — Hybrid identifiers for AD ↔ Entra cross-referencing.
	if dn := u.GetOnPremisesDistinguishedName(); dn != nil {
		user.AzureOnPremisesDistinguishedName = dn
	}
	if sid := u.GetOnPremisesSecurityIdentifier(); sid != nil {
		user.AzureOnPremisesSecurityIdentifier = sid
	}
	if iid := u.GetOnPremisesImmutableId(); iid != nil {
		user.AzureOnPremisesImmutableID = iid
	}
	if sam := u.GetOnPremisesSamAccountName(); sam != nil {
		user.AzureOnPremisesSamAccountName = sam
	}

	// v3.1.39 §2 — creationType for audit.firstPartyAccounts orphan detection.
	if ct := u.GetCreationType(); ct != nil {
		user.AzureCreationType = ct
	}

	// Convert assigned licenses to SKU IDs (assignedLicenses already in $select)
	if licenses := u.GetAssignedLicenses(); licenses != nil {
		var skuIds []string
		for _, license := range licenses {
			if skuId := license.GetSkuId(); skuId != nil {
				skuIds = append(skuIds, skuId.String())
			}
		}
		user.AzureAssignedLicenses = skuIds
	}

	return user
}

// convertAzureGroup converts an Azure AD group to our Group type
func convertAzureGroup(g models.Groupable) types.Group {
	group := types.Group{}

	if id := g.GetId(); id != nil {
		group.ObjectSID = *id
	}
	if name := g.GetDisplayName(); name != nil {
		group.SAMAccountName = *name
		group.DisplayName = *name
	}
	if desc := g.GetDescription(); desc != nil {
		group.Description = *desc
	}

	// Azure-specific fields
	if groupTypes := g.GetGroupTypes(); groupTypes != nil {
		group.AzureGroupTypes = groupTypes
	}
	if securityEnabled := g.GetSecurityEnabled(); securityEnabled != nil {
		group.AzureSecurityEnabled = securityEnabled
	}
	if mailEnabled := g.GetMailEnabled(); mailEnabled != nil {
		group.AzureMailEnabled = mailEnabled
	}
	if membershipRule := g.GetMembershipRule(); membershipRule != nil {
		group.AzureMembershipRule = membershipRule
	}
	if membershipRuleProcessingState := g.GetMembershipRuleProcessingState(); membershipRuleProcessingState != nil {
		group.AzureMembershipRuleProcessingState = membershipRuleProcessingState
	}
	if isAssignableToRole := g.GetIsAssignableToRole(); isAssignableToRole != nil {
		group.AzureIsAssignableToRole = isAssignableToRole
	}
	if visibility := g.GetVisibility(); visibility != nil {
		group.AzureVisibility = visibility
	}
	if createdDateTime := g.GetCreatedDateTime(); createdDateTime != nil {
		group.AzureCreatedDateTime = createdDateTime
	}
	if onPremisesSyncEnabled := g.GetOnPremisesSyncEnabled(); onPremisesSyncEnabled != nil {
		group.AzureOnPremisesSyncEnabled = onPremisesSyncEnabled
	}

	return group
}

// extractSAMFromUPN extracts sAMAccountName from UPN (user@domain.com -> user)
func extractSAMFromUPN(upn string) string {
	for i, c := range upn {
		if c == '@' {
			return upn[:i]
		}
	}
	return upn
}

// getAccessToken retrieves an OAuth2 access token for Microsoft Graph API
// Reuses the same credential instance as the SDK — same auth method (secret or
// certificate) and the same underlying token cache.
func (c *Client) getAccessToken(ctx context.Context) (string, error) {
	cred, err := c.credential()
	if err != nil {
		return "", fmt.Errorf("failed to create credential: %w", err)
	}

	token, err := cred.GetToken(ctx, policy.TokenRequestOptions{
		Scopes: []string{"https://graph.microsoft.com/.default"},
	})
	if err != nil {
		return "", fmt.Errorf("failed to get token: %w", err)
	}

	return token.Token, nil
}

// callGraphHTTP makes a direct HTTP call to Microsoft Graph API
// Used for endpoints not yet supported by msgraph-sdk-go
func (c *Client) callGraphHTTP(ctx context.Context, method, endpoint string, headers map[string]string) ([]byte, error) {
	return c.callGraphHTTPRaw(ctx, "v1.0", method, endpoint, headers)
}

// callGraphHTTPRaw is the underlying HTTP wrapper. version is "v1.0" or
// "beta" — the latter is required for sign-in logs (riskEventTypes_v2,
// incomingTokenType, resourceDisplayName are beta-only). Honors 429
// Retry-After (integer seconds or HTTP-date) with exponential backoff,
// max 5 attempts, capped at 60 s per wait. Returns the response body on
// 2xx, error otherwise.
//
// endpoint may be a path ("/auditLogs/signIns?…") or an absolute Graph URL
// (the @odata.nextLink from a previous page). Absolute URLs override the
// version prefix.
func (c *Client) callGraphHTTPRaw(ctx context.Context, version, method, endpoint string, headers map[string]string) ([]byte, error) {
	token, err := c.getAccessToken(ctx)
	if err != nil {
		return nil, err
	}

	var url string
	if strings.HasPrefix(endpoint, "https://") || strings.HasPrefix(endpoint, "http://") {
		url = endpoint
	} else {
		base := c.graphBaseURL
		if base == "" {
			base = "https://graph.microsoft.com/"
		}
		url = base + version + endpoint
	}

	const maxAttempts = 5
	client := &http.Client{Timeout: 60 * time.Second}
	var lastErr error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		req, err := http.NewRequestWithContext(ctx, method, url, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create request: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		for k, v := range headers {
			req.Header.Set(k, v)
		}

		resp, err := client.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("failed to execute request: %w", err)
			// transient network error — backoff and retry
			if !sleepCtx(ctx, backoffDuration(attempt, 0)) {
				return nil, lastErr
			}
			continue
		}
		body, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()
		if readErr != nil {
			return nil, fmt.Errorf("failed to read response body: %w", readErr)
		}

		if resp.StatusCode == 429 || resp.StatusCode == 503 {
			retryAfter := parseRetryAfter(resp.Header.Get("Retry-After"))
			wait := backoffDuration(attempt, retryAfter)
			lastErr = fmt.Errorf("Graph API throttled (status %d, attempt %d/%d): %s", resp.StatusCode, attempt+1, maxAttempts, string(body))
			if !sleepCtx(ctx, wait) {
				return nil, lastErr
			}
			continue
		}

		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return nil, fmt.Errorf("Graph API error %d: %s", resp.StatusCode, string(body))
		}
		return body, nil
	}
	return nil, lastErr
}

// parseRetryAfter accepts either an integer (seconds) or an HTTP-date and
// returns a duration. Returns 0 when the header is empty or unparseable —
// the caller falls back to exponential backoff in that case.
func parseRetryAfter(s string) time.Duration {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}
	if secs, err := strconv.Atoi(s); err == nil {
		if secs < 0 {
			return 0
		}
		return time.Duration(secs) * time.Second
	}
	if t, err := http.ParseTime(s); err == nil {
		d := time.Until(t)
		if d < 0 {
			return 0
		}
		return d
	}
	return 0
}

// backoffDuration combines server-suggested Retry-After (when present) with
// exponential backoff, both capped at 60 s.
func backoffDuration(attempt int, hint time.Duration) time.Duration {
	const maxWait = 60 * time.Second
	exp := time.Duration(1<<attempt) * time.Second // 1, 2, 4, 8, 16
	wait := exp
	if hint > wait {
		wait = hint
	}
	if wait > maxWait {
		wait = maxWait
	}
	return wait
}

// parseGraphMinAllowedTime extracts the minimum acceptable activityDateTime
// from a Graph 400 error message of the form:
//
//	"Minimum allowed time for activityDateTime is 4/5/2026 12:00:00 AM"
//
// Used by GetDirectoryAudits to clamp the lookback window when the tenant's
// audit-log retention is shorter than the requested days (typical on tenants
// without an Entra P1/P2 license — retention drops from 90 to ~30 days).
//
// Microsoft serialises the AM/PM separator as U+202F (NARROW NO-BREAK SPACE)
// — verified via xxd on a real prod 400 — so we normalise NBSP variants to
// regular ASCII space before searching/parsing. Without this every parse
// silently returned ok=false and the goroutines fell into the 400 path.
//
// Returns ok=false when no recognizable timestamp is present so the caller
// can fall through to its existing error path.
func parseGraphMinAllowedTime(msg string) (time.Time, bool) {
	const marker = "Minimum allowed time for activityDateTime is "
	idx := strings.Index(msg, marker)
	if idx < 0 {
		return time.Time{}, false
	}
	tail := msg[idx+len(marker):]
	// Normalise NBSP variants to ASCII space so " AM" / " PM" search and
	// time.Parse both work. U+00A0 = NBSP, U+202F = NARROW NBSP (used by
	// Microsoft), U+2009 = THIN SPACE (covering bases for other locales).
	tail = strings.NewReplacer(
		" ", " ",
		" ", " ",
		" ", " ",
	).Replace(tail)
	// Graph format: M/D/YYYY h:mm:ss AM/PM (US-style, 12h). Slice up to and
	// including the AM/PM marker so trailing garbage in the message body
	// (closing parens, quotes, follow-on text) doesn't fail time.Parse.
	upper := strings.ToUpper(tail)
	end := -1
	for _, suffix := range []string{" AM", " PM"} {
		if i := strings.Index(upper, suffix); i >= 0 {
			end = i + len(suffix)
			break
		}
	}
	if end < 0 {
		return time.Time{}, false
	}
	candidate := strings.TrimSpace(tail[:end])
	for _, layout := range []string{
		"1/2/2006 3:04:05 PM",
		"1/2/2006 03:04:05 PM",
		"01/02/2006 3:04:05 PM",
		"01/02/2006 03:04:05 PM",
	} {
		if t, err := time.Parse(layout, candidate); err == nil {
			return t.UTC(), true
		}
	}
	return time.Time{}, false
}

// sleepCtx waits for d or until ctx is cancelled. Returns true if the wait
// completed (caller may retry), false if ctx was cancelled (caller aborts).
func sleepCtx(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return true
	}
	select {
	case <-time.After(d):
		return true
	case <-ctx.Done():
		return false
	}
}

// PermissionCheck represents the result of testing a single Microsoft Graph permission.
type PermissionCheck struct {
	Permission string `json:"permission"`
	Endpoint   string `json:"endpoint"`
	Granted    bool   `json:"granted"`
	Error      string `json:"error,omitempty"`
	Reason     string `json:"reason,omitempty"` // "not_consented", "probe_failed", "p2_or_not_consented"
}

// requiredPermissions maps each Graph API permission to a lightweight test endpoint.
var requiredPermissions = []struct {
	permission string
	endpoint   string
}{
	{"Directory.Read.All", "/organization"},
	{"User.Read.All", "/users?$top=1&$select=id"},
	{"Group.Read.All", "/groups?$top=1&$select=id"},
	{"Application.Read.All", "/applications?$top=1&$select=id"},
	{"RoleManagement.Read.All", "/directoryRoles"},
	{"RoleManagementPolicy.Read.Directory", "/roleManagement/directory/roleEligibilityScheduleInstances?$top=1"},
	{"Policy.Read.All", "/identity/conditionalAccess/policies?$top=1"},
	{"AuditLog.Read.All", "/auditLogs/signIns?$top=1"},
	{"DelegatedPermissionGrant.Read.All", "/oauth2PermissionGrants?$top=1"},
	{"CrossTenantInformation.ReadBasic.All", "/policies/crossTenantAccessPolicy/default?$top=1"},
	{"IdentityRiskyUser.Read.All", "/identityProtection/riskyUsers?$top=1"},
	{"Organization.Read.All", "/organization"},
	{"UserAuthenticationMethod.Read.All", "/reports/authenticationMethods/userRegistrationDetails?$top=1"},
}

// CheckPermissions tests each required Microsoft Graph API permission by making
// a lightweight call ($top=1) to a representative endpoint. Returns a result
// per permission with Granted=true/false.
func (c *Client) CheckPermissions(ctx context.Context) []PermissionCheck {
	results := make([]PermissionCheck, len(requiredPermissions))
	var wg sync.WaitGroup

	for i, perm := range requiredPermissions {
		results[i] = PermissionCheck{
			Permission: perm.permission,
			Endpoint:   perm.endpoint,
		}
		wg.Add(1)
		go func(idx int, endpoint string) {
			defer wg.Done()
			checkCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()

			statusCode, err := c.probeEndpoint(checkCtx, endpoint)
			if err != nil {
				results[idx].Granted = false
				results[idx].Error = err.Error()
				results[idx].Reason = "probe_failed"
				return
			}
			if statusCode >= 200 && statusCode < 300 {
				results[idx].Granted = true
			} else if statusCode == 403 || statusCode == 401 {
				results[idx].Granted = false
				results[idx].Error = fmt.Sprintf("%d Forbidden", statusCode)
				if results[idx].Permission == "IdentityRiskyUser.Read.All" {
					results[idx].Reason = "p2_or_not_consented"
				} else {
					results[idx].Reason = "not_consented"
				}
			} else {
				results[idx].Granted = false
				results[idx].Error = fmt.Sprintf("HTTP %d", statusCode)
				results[idx].Reason = "probe_failed"
			}
		}(i, perm.endpoint)
	}

	wg.Wait()
	return results
}

// probeEndpoint makes a lightweight GET to a Graph API endpoint and returns the
// HTTP status code without reading the full body. Used by CheckPermissions.
func (c *Client) probeEndpoint(ctx context.Context, endpoint string) (int, error) {
	token, err := c.getAccessToken(ctx)
	if err != nil {
		return 0, fmt.Errorf("token error: %w", err)
	}

	url := "https://graph.microsoft.com/v1.0" + endpoint
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	resp.Body.Close()
	return resp.StatusCode, nil
}

// getTopLimit returns the Top query parameter for Graph API calls
// If maxResults is 0, returns nil (no limit)
// Otherwise returns a pointer to maxResults
func getTopLimit(maxResults int) *int32 {
	if maxResults == 0 {
		return nil // No limit
	}
	return int32Ptr(int32(maxResults))
}

// int32Ptr returns a pointer to an int32
func int32Ptr(i int32) *int32 {
	return &i
}

// strPtr returns a pointer to a string
func strPtr(s string) *string {
	return &s
}
