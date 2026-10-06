package audit

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/etcsec-com/etc-collector/pkg/types"
)

// mockDetector implements Detector for testing
type mockDetector struct {
	BaseDetector
}

func (m *mockDetector) Detect(ctx context.Context, data *DetectorData) []types.Finding {
	return nil
}

func (m *mockDetector) Doc() DetectorDoc {
	return DetectorDoc{Title: "Mock", Severity: types.SeverityInfo}
}

func newMockDetector(id string, cat DetectorCategory) *mockDetector {
	return &mockDetector{
		BaseDetector: NewBaseDetector(id, cat),
	}
}

func TestRegistry_Register(t *testing.T) {
	r := NewRegistry()

	d1 := newMockDetector("TEST_1", CategoryAccounts)
	d2 := newMockDetector("TEST_2", CategoryAccounts)
	d3 := newMockDetector("TEST_3", CategoryGroups)

	// Register first detector
	err := r.Register(d1)
	require.NoError(t, err)
	assert.Equal(t, 1, r.Count())

	// Register second detector
	err = r.Register(d2)
	require.NoError(t, err)
	assert.Equal(t, 2, r.Count())

	// Register third detector in different category
	err = r.Register(d3)
	require.NoError(t, err)
	assert.Equal(t, 3, r.Count())

	// Can't register duplicate
	err = r.Register(d1)
	require.Error(t, err)
}

func TestRegistry_Get(t *testing.T) {
	r := NewRegistry()

	d := newMockDetector("TEST_GET", CategoryAccounts)
	r.Register(d)

	// Get existing
	found, ok := r.Get("TEST_GET")
	assert.True(t, ok)
	assert.Equal(t, d, found)

	// Get non-existing
	found, ok = r.Get("NONEXISTENT")
	assert.False(t, ok)
	assert.Nil(t, found)
}

func TestRegistry_GetByCategory(t *testing.T) {
	r := NewRegistry()

	d1 := newMockDetector("ACC_1", CategoryAccounts)
	d2 := newMockDetector("ACC_2", CategoryAccounts)
	d3 := newMockDetector("GRP_1", CategoryGroups)

	r.Register(d1)
	r.Register(d2)
	r.Register(d3)

	// Get accounts
	accounts := r.GetByCategory(CategoryAccounts)
	assert.Len(t, accounts, 2)

	// Get groups
	groups := r.GetByCategory(CategoryGroups)
	assert.Len(t, groups, 1)

	// Get empty category
	computers := r.GetByCategory(CategoryComputers)
	assert.Len(t, computers, 0)
}

func TestRegistry_All(t *testing.T) {
	r := NewRegistry()

	r.Register(newMockDetector("D1", CategoryAccounts))
	r.Register(newMockDetector("D2", CategoryGroups))
	r.Register(newMockDetector("D3", CategoryComputers))

	all := r.All()
	assert.Len(t, all, 3)
}

func TestRegistry_Categories(t *testing.T) {
	r := NewRegistry()

	r.Register(newMockDetector("D1", CategoryAccounts))
	r.Register(newMockDetector("D2", CategoryGroups))
	r.Register(newMockDetector("D3", CategoryAccounts))

	cats := r.Categories()
	assert.Len(t, cats, 2)
	assert.Contains(t, cats, CategoryAccounts)
	assert.Contains(t, cats, CategoryGroups)
}

func TestBaseDetector(t *testing.T) {
	bd := NewBaseDetector("TEST_ID", CategoryAccounts)

	assert.Equal(t, "TEST_ID", bd.ID())
	assert.Equal(t, CategoryAccounts, bd.Category())
}
