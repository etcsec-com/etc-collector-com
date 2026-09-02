// B_157/T_058 — ten best-effort Azure fetches in collectAzureData used to
// drop their error on `err == nil` failure: the field stayed nil and every
// downstream detector read that as "nothing to report" rather than "could
// not read". This is the exact pattern that hid the GetRoleAssignments bug
// (B_156) for 5 months. This test proves the fix for one of the ten (the
// acceptance criterion's own bar — "au moins un des dix appels") using the
// collector's existing Warning mechanism rather than a new invented signal.
package audit_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/providers"
	"github.com/etcsec-com/etc-collector/internal/providers/azure"
	"github.com/etcsec-com/etc-collector/pkg/types"

	_ "github.com/etcsec-com/etc-collector/internal/audit/detectors/azure"
)

// collectionFailureProvider implements audit.AzureProvider with every
// best-effort fetch succeeding empty, except GetRoleAssignments which
// returns the injected error — reproducing a live GetRoleAssignments 400
// (or any other collection failure) without a live tenant.
type collectionFailureProvider struct {
	getRoleAssignmentsErr error
}

func (p *collectionFailureProvider) Type() providers.ProviderType  { return providers.ProviderTypeAzure }
func (p *collectionFailureProvider) Connect(context.Context) error { return nil }
func (p *collectionFailureProvider) Close() error                  { return nil }
func (p *collectionFailureProvider) IsConnected() bool             { return true }

func (p *collectionFailureProvider) GetUsers(context.Context, providers.QueryOptions) ([]types.User, error) {
	return nil, nil
}
func (p *collectionFailureProvider) GetGroups(context.Context, providers.QueryOptions) ([]types.Group, error) {
	return nil, nil
}
func (p *collectionFailureProvider) GetComputers(context.Context, providers.QueryOptions) ([]types.Computer, error) {
	return nil, nil
}
func (p *collectionFailureProvider) GetDomainInfo(context.Context) (*types.DomainInfo, error) {
	return nil, nil
}

func (p *collectionFailureProvider) GetConditionalAccessPolicies(context.Context) ([]types.ConditionalAccessPolicy, error) {
	return nil, nil
}
func (p *collectionFailureProvider) GetDirectoryRoles(context.Context) ([]types.DirectoryRole, error) {
	return nil, nil
}
func (p *collectionFailureProvider) GetRoleAssignments(context.Context) ([]types.RoleAssignment, error) {
	return nil, p.getRoleAssignmentsErr
}
func (p *collectionFailureProvider) GetAppRegistrations(context.Context, providers.QueryOptions) ([]types.AppRegistration, error) {
	return nil, nil
}
func (p *collectionFailureProvider) GetServicePrincipals(context.Context, providers.QueryOptions) ([]types.ServicePrincipal, error) {
	return nil, nil
}
func (p *collectionFailureProvider) GetOAuth2PermissionGrants(context.Context) ([]types.OAuth2PermissionGrant, error) {
	return nil, nil
}
func (p *collectionFailureProvider) GetAuthMethodsPolicy(context.Context) (*types.AuthMethodsPolicy, error) {
	return nil, nil
}
func (p *collectionFailureProvider) GetNamedLocations(context.Context) ([]types.NamedLocation, error) {
	return nil, nil
}
func (p *collectionFailureProvider) GetRiskyUsers(context.Context) ([]types.RiskyUser, error) {
	return nil, nil
}
func (p *collectionFailureProvider) GetRiskySignIns(context.Context) ([]types.RiskySignIn, error) {
	return nil, nil
}
func (p *collectionFailureProvider) GetSecurityDefaults(context.Context) (*types.TenantSecurityDefaults, error) {
	return nil, nil
}
func (p *collectionFailureProvider) GetTenantConfig(context.Context) (*types.AzureTenantConfig, error) {
	// Real implementations never return (nil, nil) — the zero-value struct
	// matches client.go's own contract (GetTenantConfig always allocates
	// before populating fields).
	return &types.AzureTenantConfig{}, nil
}
func (p *collectionFailureProvider) GetLicenseTier(context.Context) string { return "" }
func (p *collectionFailureProvider) GetMFARegistrationReport(context.Context) (*azure.MFARegistrationReport, error) {
	return nil, nil
}
func (p *collectionFailureProvider) GetSignInLogs(context.Context, int, int) ([]types.SignInLog, bool, time.Time, error) {
	return nil, false, time.Time{}, nil
}

// TestCollectAzureData_FailedFetchProducesWarning is the "at least one of the
// ten" proof the acceptance criteria ask for: a GetRoleAssignments failure
// must surface as an explicit Warning on the audit result, not silence.
func TestCollectAzureData_FailedFetchProducesWarning(t *testing.T) {
	simulated := errors.New("simulated Graph 400: Only one property can be expanded in a single query")
	provider := &collectionFailureProvider{getRoleAssignmentsErr: simulated}

	engine := audit.NewEngine(audit.DefaultRegistry, provider)
	result, err := engine.Run(context.Background(), audit.RunOptions{})
	require.NoError(t, err)

	var found *types.Warning
	for i := range result.Warnings {
		if result.Warnings[i].Code == "AZURE_ROLE_ASSIGNMENTS_FAILED" {
			found = &result.Warnings[i]
			break
		}
	}
	require.NotNil(t, found, "a failed GetRoleAssignments must produce an AZURE_ROLE_ASSIGNMENTS_FAILED warning instead of silence")
	assert.Contains(t, found.Message, simulated.Error())
}

// TestCollectAzureData_SuccessfulFetchProducesNoFailureWarning is the
// negative control: a clean collection must not spuriously warn.
func TestCollectAzureData_SuccessfulFetchProducesNoFailureWarning(t *testing.T) {
	provider := &collectionFailureProvider{}

	engine := audit.NewEngine(audit.DefaultRegistry, provider)
	result, err := engine.Run(context.Background(), audit.RunOptions{})
	require.NoError(t, err)

	for _, w := range result.Warnings {
		assert.NotEqual(t, "AZURE_ROLE_ASSIGNMENTS_FAILED", w.Code, "a successful collection must not warn")
	}
}
