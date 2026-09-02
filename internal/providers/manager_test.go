package providers

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/etcsec-com/etc-collector/pkg/types"
)

// mockProvider implements Provider for testing
type mockProvider struct {
	ptype     ProviderType
	connected bool
}

func (m *mockProvider) Type() ProviderType                { return m.ptype }
func (m *mockProvider) Connect(ctx context.Context) error { m.connected = true; return nil }
func (m *mockProvider) Close() error                      { m.connected = false; return nil }
func (m *mockProvider) IsConnected() bool                 { return m.connected }
func (m *mockProvider) GetUsers(ctx context.Context, opts QueryOptions) ([]types.User, error) {
	return nil, nil
}
func (m *mockProvider) GetGroups(ctx context.Context, opts QueryOptions) ([]types.Group, error) {
	return nil, nil
}
func (m *mockProvider) GetComputers(ctx context.Context, opts QueryOptions) ([]types.Computer, error) {
	return nil, nil
}
func (m *mockProvider) GetDomainInfo(ctx context.Context) (*types.DomainInfo, error) {
	return &types.DomainInfo{}, nil
}

func TestManager_Register(t *testing.T) {
	manager := NewManager()

	ldap := &mockProvider{ptype: ProviderTypeLDAP}
	azure := &mockProvider{ptype: ProviderTypeAzure}

	// Register first provider
	err := manager.Register(ldap)
	require.NoError(t, err)
	assert.Equal(t, 1, manager.Count())

	// First provider becomes primary
	assert.Equal(t, ldap, manager.Primary())

	// Register second provider
	err = manager.Register(azure)
	require.NoError(t, err)
	assert.Equal(t, 2, manager.Count())

	// Primary should still be LDAP
	assert.Equal(t, ldap, manager.Primary())

	// Can't register same type twice
	ldap2 := &mockProvider{ptype: ProviderTypeLDAP}
	err = manager.Register(ldap2)
	require.Error(t, err)
}

func TestManager_Get(t *testing.T) {
	manager := NewManager()

	ldap := &mockProvider{ptype: ProviderTypeLDAP}
	manager.Register(ldap)

	// Get existing provider
	p, ok := manager.Get(ProviderTypeLDAP)
	assert.True(t, ok)
	assert.Equal(t, ldap, p)

	// Get non-existing provider
	p, ok = manager.Get(ProviderTypeAzure)
	assert.False(t, ok)
	assert.Nil(t, p)
}

func TestManager_SetPrimary(t *testing.T) {
	manager := NewManager()

	ldap := &mockProvider{ptype: ProviderTypeLDAP}
	azure := &mockProvider{ptype: ProviderTypeAzure}

	manager.Register(ldap)
	manager.Register(azure)

	// Change primary
	err := manager.SetPrimary(ProviderTypeAzure)
	require.NoError(t, err)
	assert.Equal(t, azure, manager.Primary())

	// Set non-existing as primary
	err = manager.SetPrimary("invalid")
	require.Error(t, err)
}

func TestManager_ConnectAll(t *testing.T) {
	manager := NewManager()

	ldap := &mockProvider{ptype: ProviderTypeLDAP}
	azure := &mockProvider{ptype: ProviderTypeAzure}

	manager.Register(ldap)
	manager.Register(azure)

	// Both should be disconnected
	assert.False(t, ldap.IsConnected())
	assert.False(t, azure.IsConnected())

	// Connect all
	err := manager.ConnectAll(context.Background())
	require.NoError(t, err)

	// Both should be connected
	assert.True(t, ldap.IsConnected())
	assert.True(t, azure.IsConnected())
}

func TestManager_CloseAll(t *testing.T) {
	manager := NewManager()

	ldap := &mockProvider{ptype: ProviderTypeLDAP, connected: true}
	azure := &mockProvider{ptype: ProviderTypeAzure, connected: true}

	manager.Register(ldap)
	manager.Register(azure)

	// Both are connected
	assert.True(t, ldap.IsConnected())
	assert.True(t, azure.IsConnected())

	// Close all
	err := manager.CloseAll()
	require.NoError(t, err)

	// Both should be disconnected
	assert.False(t, ldap.IsConnected())
	assert.False(t, azure.IsConnected())
}

func TestManager_GetInfo(t *testing.T) {
	manager := NewManager()

	ldap := &mockProvider{ptype: ProviderTypeLDAP, connected: true}
	azure := &mockProvider{ptype: ProviderTypeAzure, connected: false}

	manager.Register(ldap)
	manager.Register(azure)

	infos := manager.GetInfo()
	assert.Len(t, infos, 2)

	// Find each provider info
	var ldapInfo, azureInfo *ProviderInfo
	for i := range infos {
		if infos[i].Type == ProviderTypeLDAP {
			ldapInfo = &infos[i]
		}
		if infos[i].Type == ProviderTypeAzure {
			azureInfo = &infos[i]
		}
	}

	require.NotNil(t, ldapInfo)
	require.NotNil(t, azureInfo)

	assert.True(t, ldapInfo.Connected)
	assert.False(t, azureInfo.Connected)
}

func TestManager_Types(t *testing.T) {
	manager := NewManager()

	manager.Register(&mockProvider{ptype: ProviderTypeLDAP})
	manager.Register(&mockProvider{ptype: ProviderTypeAzure})

	types := manager.Types()
	assert.Len(t, types, 2)
	assert.Contains(t, types, ProviderTypeLDAP)
	assert.Contains(t, types, ProviderTypeAzure)
}

func TestProviderError(t *testing.T) {
	err := NewProviderError(ProviderTypeLDAP, "connect", assert.AnError)

	assert.Equal(t, ProviderTypeLDAP, err.Provider)
	assert.Equal(t, "connect", err.Op)
	assert.ErrorIs(t, err, assert.AnError)
	assert.Contains(t, err.Error(), "ldap")
	assert.Contains(t, err.Error(), "connect")
}
