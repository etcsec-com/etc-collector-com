// Package providers defines the interface for identity providers
package providers

import (
	"context"

	"github.com/etcsec-com/etc-collector/pkg/types"
)

// ProviderType represents the type of provider
type ProviderType string

const (
	ProviderTypeLDAP     ProviderType = "ldap"
	ProviderTypeAzure    ProviderType = "azure"
	ProviderTypeIntune   ProviderType = "intune"
	ProviderTypeExchange ProviderType = "exchange"
	ProviderTypeGoogle   ProviderType = "google"
)

// QueryOptions contains options for querying objects
type QueryOptions struct {
	MaxResults int      // Maximum number of results (0 = unlimited)
	Filter     string   // Custom LDAP filter or OData filter
	Attributes []string // Specific attributes to retrieve
	PageSize   int      // Page size for pagination
}

// Provider is the interface that all identity providers must implement
type Provider interface {
	// Type returns the provider type
	Type() ProviderType

	// Connect establishes a connection to the provider
	Connect(ctx context.Context) error

	// Close closes the connection
	Close() error

	// IsConnected returns true if connected
	IsConnected() bool

	// GetUsers retrieves users from the directory
	GetUsers(ctx context.Context, opts QueryOptions) ([]types.User, error)

	// GetGroups retrieves groups from the directory
	GetGroups(ctx context.Context, opts QueryOptions) ([]types.Group, error)

	// GetComputers retrieves computer accounts from the directory
	GetComputers(ctx context.Context, opts QueryOptions) ([]types.Computer, error)

	// GetDomainInfo retrieves domain-level information
	GetDomainInfo(ctx context.Context) (*types.DomainInfo, error)
}

// ExtendedProvider provides additional capabilities beyond basic Provider
type ExtendedProvider interface {
	Provider

	// GetGPOs retrieves Group Policy Objects
	GetGPOs(ctx context.Context) ([]types.GPO, error)

	// GetTrusts retrieves domain trusts
	GetTrusts(ctx context.Context) ([]types.Trust, error)

	// GetCertTemplates retrieves certificate templates (AD CS)
	GetCertTemplates(ctx context.Context) ([]types.CertTemplate, error)

	// GetObjectACL retrieves the ACL for a specific object
	GetObjectACL(ctx context.Context, dn string) ([]types.ACE, error)
}

// ProviderInfo contains metadata about a provider
type ProviderInfo struct {
	Type        ProviderType `json:"type"`
	Connected   bool         `json:"connected"`
	Domain      string       `json:"domain,omitempty"`
	Server      string       `json:"server,omitempty"`
	TenantID    string       `json:"tenantId,omitempty"`
	LastConnect string       `json:"lastConnect,omitempty"`
	Error       string       `json:"error,omitempty"`
}

// ProviderError represents a provider-specific error
type ProviderError struct {
	Provider ProviderType
	Op       string
	Err      error
}

func (e *ProviderError) Error() string {
	return string(e.Provider) + ": " + e.Op + ": " + e.Err.Error()
}

func (e *ProviderError) Unwrap() error {
	return e.Err
}

// NewProviderError creates a new provider error.
// If a classifier was registered for the provider via RegisterClassifier,
// the underlying error is passed through it first so that callers see a
// stable structured error code (e.g., LDAP_REFERRAL_BAD_BASE_DN) instead
// of the raw upstream message.
func NewProviderError(provider ProviderType, op string, err error) *ProviderError {
	if fn, ok := classifiers[provider]; ok && err != nil {
		err = fn(err)
	}
	return &ProviderError{
		Provider: provider,
		Op:       op,
		Err:      err,
	}
}

// classifiers is a per-provider error classification registry. Provider
// packages register themselves in their init() to avoid an import cycle
// (providers → providers/ldap would be a cycle).
var classifiers = map[ProviderType]func(error) error{}

// RegisterClassifier registers a classifier function for a provider type.
// Called from the provider package's init() — must be idempotent (last
// registration wins, in practice there is only one per type).
func RegisterClassifier(provider ProviderType, fn func(error) error) {
	classifiers[provider] = fn
}
