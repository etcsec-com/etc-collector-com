package providers

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// Manager manages multiple providers
type Manager struct {
	mu        sync.RWMutex
	providers map[ProviderType]Provider
	primary   ProviderType
}

// NewManager creates a new provider manager
func NewManager() *Manager {
	return &Manager{
		providers: make(map[ProviderType]Provider),
	}
}

// Register registers a provider
func (m *Manager) Register(p Provider) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	ptype := p.Type()
	if _, exists := m.providers[ptype]; exists {
		return fmt.Errorf("provider %s already registered", ptype)
	}

	m.providers[ptype] = p

	// First provider becomes primary
	if m.primary == "" {
		m.primary = ptype
	}

	return nil
}

// Replace closes an existing provider of the same type and registers the new one
func (m *Manager) Replace(p Provider) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	ptype := p.Type()
	if old, exists := m.providers[ptype]; exists {
		old.Close()
	}
	m.providers[ptype] = p

	// Same rule Register() applies: the first provider ever added claims
	// primary (T_138). Without this, a caller that only ever calls Replace()
	// — updateLDAPConfigHandler in standalone mode, internal/api/admin.go —
	// left m.primary permanently empty, so Primary() (and therefore
	// auditStatusHandler's GET /api/v1/audit/ad/status) reported
	// not_configured forever even after a successful configure+connect.
	// Gating on empty, rather than always overwriting, matters just as much:
	// it keeps this a no-op for every daemon.go call site (internal/saas),
	// where Replace() only ever runs after Register() already established a
	// primary for that same type — and it means replacing/adding a second
	// provider type can never silently steal primary from a type that's
	// already active.
	if m.primary == "" {
		m.primary = ptype
	}

	return nil
}

// SetPrimary sets the primary provider
func (m *Manager) SetPrimary(ptype ProviderType) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.providers[ptype]; !exists {
		return fmt.Errorf("provider %s not registered", ptype)
	}

	m.primary = ptype
	return nil
}

// Get returns a provider by type
func (m *Manager) Get(ptype ProviderType) (Provider, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	p, exists := m.providers[ptype]
	return p, exists
}

// Primary returns the primary provider
func (m *Manager) Primary() Provider {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return m.providers[m.primary]
}

// ConnectAll connects all registered providers
func (m *Manager) ConnectAll(ctx context.Context) error {
	m.mu.RLock()
	providers := make([]Provider, 0, len(m.providers))
	for _, p := range m.providers {
		providers = append(providers, p)
	}
	m.mu.RUnlock()

	var errs []error
	for _, p := range providers {
		if err := p.Connect(ctx); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", p.Type(), err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("failed to connect providers: %v", errs)
	}

	return nil
}

// CloseAll closes all providers
func (m *Manager) CloseAll() error {
	m.mu.RLock()
	providers := make([]Provider, 0, len(m.providers))
	for _, p := range m.providers {
		providers = append(providers, p)
	}
	m.mu.RUnlock()

	var errs []error
	for _, p := range providers {
		if err := p.Close(); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", p.Type(), err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("failed to close providers: %v", errs)
	}

	return nil
}

// GetInfo returns information about all registered providers
func (m *Manager) GetInfo() []ProviderInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()

	infos := make([]ProviderInfo, 0, len(m.providers))
	for ptype, p := range m.providers {
		info := ProviderInfo{
			Type:      ptype,
			Connected: p.IsConnected(),
		}
		infos = append(infos, info)
	}

	return infos
}

// HealthCheck performs a health check on all providers
func (m *Manager) HealthCheck(ctx context.Context) map[ProviderType]error {
	m.mu.RLock()
	providers := make(map[ProviderType]Provider, len(m.providers))
	for k, v := range m.providers {
		providers[k] = v
	}
	m.mu.RUnlock()

	results := make(map[ProviderType]error)

	for ptype, p := range providers {
		// Check connection
		if !p.IsConnected() {
			results[ptype] = fmt.Errorf("not connected")
			continue
		}

		// Try a simple query
		ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		_, err := p.GetDomainInfo(ctx)
		cancel()

		results[ptype] = err
	}

	return results
}

// Types returns the types of all registered providers
func (m *Manager) Types() []ProviderType {
	m.mu.RLock()
	defer m.mu.RUnlock()

	types := make([]ProviderType, 0, len(m.providers))
	for t := range m.providers {
		types = append(types, t)
	}

	return types
}

// Count returns the number of registered providers
func (m *Manager) Count() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.providers)
}

// All returns all registered providers
func (m *Manager) All() []Provider {
	m.mu.RLock()
	defer m.mu.RUnlock()

	providers := make([]Provider, 0, len(m.providers))
	for _, p := range m.providers {
		providers = append(providers, p)
	}
	return providers
}

// GetDefault is an alias for Primary for compatibility
func (m *Manager) GetDefault() Provider {
	return m.Primary()
}

// List is an alias for All for compatibility
func (m *Manager) List() []Provider {
	return m.All()
}
