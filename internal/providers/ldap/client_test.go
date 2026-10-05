package ldap

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/etcsec-com/etc-collector/internal/providers"
	"github.com/etcsec-com/etc-collector/pkg/types"
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

// GetGPOAcls converted types.ACLEntry to audit.GPOAcl via a straight
// AccessMask pass-through, so the CONTROL_ACCESS bit (0x00000100) survived
// with no way to tell WHICH extended right it meant: audit.GPOAcl has no
// ObjectType field to carry the GUID (it is shared core).
// gpoAclFromACLEntry now resolves that bit here, where
// ObjectType is still available on the source ACE, before it's lost.
//
// The first case is the red->green proof: a DELETE-only ACE (0x00010000,
// ADS_RIGHT_DELETE) is what the two GPO detectors checked for by mistake -
// this asserts the CONTROL_ACCESS bit they now check is NOT set for it.
func TestGpoAclFromACLEntry(t *testing.T) {
	const guidApplyGroupPolicy = "edacfd8f-ffb3-11d1-b41d-00a0c968f939"
	const guidOtherExtendedRight = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2" // DS-Replication-Get-Changes

	tests := []struct {
		name           string
		ace            types.ACLEntry
		wantControlBit bool
	}{
		{
			name:           "DELETE alone does not resolve to Apply-Group-Policy",
			ace:            types.ACLEntry{AccessMask: 0x00010000},
			wantControlBit: false,
		},
		{
			name:           "CONTROL_ACCESS + Apply-Group-Policy GUID resolves",
			ace:            types.ACLEntry{AccessMask: types.MaskControlAccess, ObjectType: guidApplyGroupPolicy},
			wantControlBit: true,
		},
		{
			name:           "CONTROL_ACCESS + empty ObjectType resolves (grants every extended right)",
			ace:            types.ACLEntry{AccessMask: types.MaskControlAccess},
			wantControlBit: true,
		},
		{
			name:           "WriteProperty + the Apply-Group-Policy GUID does not resolve (wrong access type)",
			ace:            types.ACLEntry{AccessMask: types.MaskWriteProperty, ObjectType: guidApplyGroupPolicy},
			wantControlBit: false,
		},
		{
			name:           "CONTROL_ACCESS + a different extended right's GUID does not resolve",
			ace:            types.ACLEntry{AccessMask: types.MaskControlAccess, ObjectType: guidOtherExtendedRight},
			wantControlBit: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.ace.ObjectDN = "CN={test},CN=Policies,CN=System,DC=example,DC=com"
			tt.ace.Trustee = "S-1-5-11"
			tt.ace.AceType = "ACCESS_ALLOWED"

			got := gpoAclFromACLEntry(tt.ace)

			assert.Equal(t, tt.wantControlBit, got.AccessMask&types.MaskControlAccess != 0)
			// Every other field/bit passes through unmodified.
			assert.Equal(t, tt.ace.ObjectDN, got.GPODN)
			assert.Equal(t, tt.ace.Trustee, got.Trustee)
			assert.Equal(t, tt.ace.AceType, got.AceType)
			assert.Equal(t, tt.ace.AccessMask&^types.MaskControlAccess, got.AccessMask&^types.MaskControlAccess)
		})
	}
}
