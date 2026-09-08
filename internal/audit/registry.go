package audit

import (
	"fmt"
	"sync"
)

// Registry contains all registered detectors
type Registry struct {
	mu         sync.RWMutex
	detectors  map[string]Detector
	byCategory map[DetectorCategory][]Detector
}

// NewRegistry creates a new registry
func NewRegistry() *Registry {
	return &Registry{
		detectors:  make(map[string]Detector),
		byCategory: make(map[DetectorCategory][]Detector),
	}
}

// Register registers a detector
func (r *Registry) Register(d Detector) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.detectors[d.ID()]; exists {
		return fmt.Errorf("detector %s already registered", d.ID())
	}

	r.detectors[d.ID()] = d
	r.byCategory[d.Category()] = append(r.byCategory[d.Category()], d)
	return nil
}

// Get returns a detector by ID
func (r *Registry) Get(id string) (Detector, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	d, ok := r.detectors[id]
	return d, ok
}

// GetByCategory returns all detectors in a category
func (r *Registry) GetByCategory(cat DetectorCategory) []Detector {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.byCategory[cat]
}

// All returns all detectors
func (r *Registry) All() []Detector {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make([]Detector, 0, len(r.detectors))
	for _, d := range r.detectors {
		result = append(result, d)
	}
	return result
}

// Count returns the number of registered detectors
func (r *Registry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.detectors)
}

// Categories returns all categories that have detectors
func (r *Registry) Categories() []DetectorCategory {
	r.mu.RLock()
	defer r.mu.RUnlock()

	cats := make([]DetectorCategory, 0, len(r.byCategory))
	for cat := range r.byCategory {
		cats = append(cats, cat)
	}
	return cats
}

// DefaultRegistry is the global registry
var DefaultRegistry = NewRegistry()

// Register registers a detector to the default registry
func Register(d Detector) error {
	return DefaultRegistry.Register(d)
}

// MustRegister registers a detector or panics
func MustRegister(d Detector) {
	if err := DefaultRegistry.Register(d); err != nil {
		panic(err)
	}
}
