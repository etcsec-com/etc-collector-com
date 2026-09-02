package ldap

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/etcsec-com/etc-collector/internal/providers"
)

func TestNewClient(t *testing.T) {
	tests := []struct {
		name    string
		cfg     Config
		wantErr bool
	}{
		{
			name: "valid config",
			cfg: Config{
				URL:          "ldaps://dc.example.com:636",
				BindDN:       "CN=service,CN=Users,DC=example,DC=com",
				BindPassword: "password",
				BaseDN:       "DC=example,DC=com",
			},
			wantErr: false,
		},
		{
			name: "missing URL",
			cfg: Config{
				BindDN:       "CN=service,CN=Users,DC=example,DC=com",
				BindPassword: "password",
				BaseDN:       "DC=example,DC=com",
			},
			wantErr: true,
		},
		{
			name: "URL only (anonymous bind)",
			cfg: Config{
				URL:    "ldap://dc.example.com:389",
				BaseDN: "DC=example,DC=com",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := NewClient(tt.cfg)

			if tt.wantErr {
				require.Error(t, err)
				assert.Nil(t, client)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, client)
				assert.Equal(t, providers.ProviderTypeLDAP, client.Type())
			}
		})
	}
}

func TestClient_DefaultValues(t *testing.T) {
	cfg := Config{
		URL:    "ldaps://dc.example.com:636",
		BaseDN: "DC=example,DC=com",
	}

	client, err := NewClient(cfg)
	require.NoError(t, err)

	// Check defaults are set
	assert.Equal(t, 30*time.Second, client.config.Timeout)
	assert.Equal(t, 1000, client.config.PageSize)
}

func TestClient_Type(t *testing.T) {
	client := &Client{}
	assert.Equal(t, providers.ProviderTypeLDAP, client.Type())
}

func TestClient_IsConnected_WhenNotConnected(t *testing.T) {
	client := &Client{}
	assert.False(t, client.IsConnected())
}

func TestFunctionalLevelToString(t *testing.T) {
	tests := []struct {
		level    int
		expected string
	}{
		{0, "2000"},
		{1, "2003 Interim"},
		{2, "2003"},
		{3, "2008"},
		{4, "2008 R2"},
		{5, "2012"},
		{6, "2012 R2"},
		{7, "2016"},
		{99, "Unknown (99)"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := functionalLevelToString(tt.level)
			assert.Equal(t, tt.expected, result)
		})
	}
}
