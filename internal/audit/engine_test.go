package audit

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/etcsec-com/etc-collector/internal/audit/exclusions"
	"github.com/etcsec-com/etc-collector/internal/providers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// testProvider implements providers.Provider for testing
type testProvider struct {
	users     []types.User
	groups    []types.Group
	computers []types.Computer
	domain    *types.DomainInfo
}

func (p *testProvider) Type() providers.ProviderType      { return providers.ProviderTypeLDAP }
func (p *testProvider) Connect(ctx context.Context) error { return nil }
func (p *testProvider) Close() error                      { return nil }
func (p *testProvider) IsConnected() bool                 { return true }

func (p *testProvider) GetUsers(ctx context.Context, opts providers.QueryOptions) ([]types.User, error) {
	return p.users, nil
}

func (p *testProvider) GetGroups(ctx context.Context, opts providers.QueryOptions) ([]types.Group, error) {
	return p.groups, nil
}

func (p *testProvider) GetComputers(ctx context.Context, opts providers.QueryOptions) ([]types.Computer, error) {
	return p.computers, nil
}

func (p *testProvider) GetDomainInfo(ctx context.Context) (*types.DomainInfo, error) {
	return p.domain, nil
}

// testDetector is a simple detector for testing
type testDetector struct {
	BaseDetector
	findings []types.Finding
}

func (d *testDetector) Detect(ctx context.Context, data *DetectorData) []types.Finding {
	return d.findings
}

func (d *testDetector) Doc() DetectorDoc {
	return DetectorDoc{Title: "Test", Severity: types.SeverityInfo}
}

func TestEngine_Run_EmptyData(t *testing.T) {
	registry := NewRegistry()
	registry.Register(&testDetector{
		BaseDetector: NewBaseDetector("TEST_1", CategoryAccounts),
		findings: []types.Finding{{
			Type:     "TEST_1",
			Severity: types.SeverityLow,
			Category: "accounts",
			Title:    "Test Finding",
			Count:    0, // Zero count = filtered out
		}},
	})

	provider := &testProvider{}
	engine := NewEngine(registry, provider)

	result, err := engine.Run(context.Background(), RunOptions{})
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, 100.0, result.Score) // No findings = perfect score
	assert.Len(t, result.Findings, 0)    // Zero-count findings filtered
}

func TestEngine_Run_WithFindings(t *testing.T) {
	registry := NewRegistry()
	registry.Register(&testDetector{
		BaseDetector: NewBaseDetector("HIGH_FINDING", CategoryAccounts),
		findings: []types.Finding{{
			Type:     "HIGH_FINDING",
			Severity: types.SeverityHigh,
			Category: "accounts",
			Title:    "High Severity Finding",
			Count:    5,
		}},
	})
	registry.Register(&testDetector{
		BaseDetector: NewBaseDetector("LOW_FINDING", CategoryGroups),
		findings: []types.Finding{{
			Type:     "LOW_FINDING",
			Severity: types.SeverityLow,
			Category: "groups",
			Title:    "Low Severity Finding",
			Count:    3,
		}},
	})

	provider := &testProvider{
		users: []types.User{
			{SAMAccountName: "user1"},
			{SAMAccountName: "user2"},
		},
	}
	engine := NewEngine(registry, provider)

	result, err := engine.Run(context.Background(), RunOptions{})
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.Len(t, result.Findings, 2)
	assert.Less(t, result.Score, 100.0) // Has findings, score < 100
	assert.Equal(t, 2, result.Statistics.UsersScanned)
}

// TestEngine_Run_CountsDisabledUsers covers T_031 / B_031: the enabled/disabled
// split is computed here because this is the only place holding the collected
// user list. The report summary used to hard-code users_disabled to 0.
func TestEngine_Run_CountsDisabledUsers(t *testing.T) {
	registry := NewRegistry()
	provider := &testProvider{
		users: []types.User{
			{SAMAccountName: "live1"},
			{SAMAccountName: "live2"},
			{SAMAccountName: "ghost1", Disabled: true},
			{SAMAccountName: "ghost2", Disabled: true},
			{SAMAccountName: "ghost3", Disabled: true},
		},
	}
	engine := NewEngine(registry, provider)

	result, err := engine.Run(context.Background(), RunOptions{})
	require.NoError(t, err)
	assert.Equal(t, 5, result.Statistics.UsersScanned)
	assert.Equal(t, 3, result.Statistics.UsersDisabled)
	assert.Equal(t, 2, result.Statistics.UsersEnabled)
	// The split must always add up — a summary that contradicts itself is the
	// defect this fixes.
	assert.Equal(t, result.Statistics.UsersScanned,
		result.Statistics.UsersEnabled+result.Statistics.UsersDisabled)
}

func TestEngine_Run_FilterByCategory(t *testing.T) {
	registry := NewRegistry()
	registry.Register(&testDetector{
		BaseDetector: NewBaseDetector("ACCOUNTS_1", CategoryAccounts),
		findings: []types.Finding{{
			Type:     "ACCOUNTS_1",
			Severity: types.SeverityHigh,
			Category: "accounts",
			Title:    "Accounts Finding",
			Count:    1,
		}},
	})
	registry.Register(&testDetector{
		BaseDetector: NewBaseDetector("GROUPS_1", CategoryGroups),
		findings: []types.Finding{{
			Type:     "GROUPS_1",
			Severity: types.SeverityHigh,
			Category: "groups",
			Title:    "Groups Finding",
			Count:    1,
		}},
	})

	provider := &testProvider{}
	engine := NewEngine(registry, provider)

	// Run only accounts category
	result, err := engine.Run(context.Background(), RunOptions{
		Categories: []DetectorCategory{CategoryAccounts},
	})
	require.NoError(t, err)
	assert.Len(t, result.Findings, 1)
	assert.Equal(t, "ACCOUNTS_1", result.Findings[0].Type)
}

func TestEngine_Run_FilterByID(t *testing.T) {
	registry := NewRegistry()
	registry.Register(&testDetector{
		BaseDetector: NewBaseDetector("DETECTOR_A", CategoryAccounts),
		findings: []types.Finding{{
			Type:  "DETECTOR_A",
			Count: 1,
		}},
	})
	registry.Register(&testDetector{
		BaseDetector: NewBaseDetector("DETECTOR_B", CategoryAccounts),
		findings: []types.Finding{{
			Type:  "DETECTOR_B",
			Count: 1,
		}},
	})

	provider := &testProvider{}
	engine := NewEngine(registry, provider)

	// Run only specific detector
	result, err := engine.Run(context.Background(), RunOptions{
		DetectorIDs: []string{"DETECTOR_A"},
	})
	require.NoError(t, err)
	assert.Len(t, result.Findings, 1)
	assert.Equal(t, "DETECTOR_A", result.Findings[0].Type)
}

func TestEngine_Run_Parallel(t *testing.T) {
	registry := NewRegistry()

	// Add multiple detectors
	for i := 0; i < 10; i++ {
		id := "TEST_" + string(rune('A'+i))
		registry.Register(&testDetector{
			BaseDetector: NewBaseDetector(id, CategoryAccounts),
			findings: []types.Finding{{
				Type:  id,
				Count: 1,
			}},
		})
	}

	provider := &testProvider{}
	engine := NewEngine(registry, provider)

	// Run in parallel
	result, err := engine.Run(context.Background(), RunOptions{
		Parallel: true,
	})
	require.NoError(t, err)
	assert.Len(t, result.Findings, 10)
}

// TestEngine_Run_ParallelFindingOrderIsDeterministic covers T_046/B_048:
// runParallel appends each detector's results to a shared slice as
// goroutines complete, which is randomized per run. Same registry, same
// data, run several times — the findings (and the buildSummary aggregate)
// must come back in the same Type order every time.
func TestEngine_Run_ParallelFindingOrderIsDeterministic(t *testing.T) {
	registry := NewRegistry()
	ids := []string{"ZULU_FINDING", "ALPHA_FINDING", "MIKE_FINDING", "BRAVO_FINDING", "KILO_FINDING"}
	for _, id := range ids {
		registry.Register(&testDetector{
			BaseDetector: NewBaseDetector(id, CategoryAccounts),
			findings:     []types.Finding{{Type: id, Severity: types.SeverityLow, Category: "accounts", Count: 1}},
		})
	}

	want := []string{"ALPHA_FINDING", "BRAVO_FINDING", "KILO_FINDING", "MIKE_FINDING", "ZULU_FINDING"}

	provider := &testProvider{}
	engine := NewEngine(registry, provider)

	for i := 0; i < 10; i++ {
		result, err := engine.Run(context.Background(), RunOptions{Parallel: true})
		require.NoError(t, err)
		require.Len(t, result.Findings, len(want))
		require.Len(t, result.Summary, len(want))
		for j, f := range result.Findings {
			assert.Equal(t, want[j], f.Type, "run %d: findings[%d] order not deterministic", i, j)
		}
		for j, s := range result.Summary {
			assert.Equal(t, want[j], s.Type, "run %d: summary[%d] order not deterministic", i, j)
		}
	}
}

func TestEngine_Run_Statistics(t *testing.T) {
	registry := NewRegistry()
	registry.Register(&testDetector{
		BaseDetector: NewBaseDetector("CRIT", CategoryAccounts),
		findings: []types.Finding{{
			Type:     "CRIT",
			Severity: types.SeverityCritical,
			Category: "accounts",
			Count:    2,
		}},
	})
	registry.Register(&testDetector{
		BaseDetector: NewBaseDetector("HIGH", CategoryGroups),
		findings: []types.Finding{{
			Type:     "HIGH",
			Severity: types.SeverityHigh,
			Category: "groups",
			Count:    3,
		}},
	})

	provider := &testProvider{
		users:     make([]types.User, 100),
		groups:    make([]types.Group, 50),
		computers: make([]types.Computer, 25),
	}
	engine := NewEngine(registry, provider)

	result, err := engine.Run(context.Background(), RunOptions{})
	require.NoError(t, err)

	assert.Equal(t, 2, result.Statistics.TotalFindings)
	assert.Equal(t, 100, result.Statistics.UsersScanned)
	assert.Equal(t, 50, result.Statistics.GroupsScanned)
	assert.Equal(t, 25, result.Statistics.ComputersScanned)
	assert.Equal(t, 1, result.Statistics.BySeverity[types.SeverityCritical])
	assert.Equal(t, 1, result.Statistics.BySeverity[types.SeverityHigh])
	assert.Equal(t, 1, result.Statistics.ByCategory["accounts"])
	assert.Equal(t, 1, result.Statistics.ByCategory["groups"])
}

func TestEngine_Run_Duration(t *testing.T) {
	registry := NewRegistry()
	provider := &testProvider{}
	engine := NewEngine(registry, provider)

	result, err := engine.Run(context.Background(), RunOptions{})
	require.NoError(t, err)

	assert.True(t, result.Duration >= 0)
	assert.False(t, result.Timestamp.IsZero())
}

func TestEngine_Run_WithStaleUsers(t *testing.T) {
	// This tests integration with real detectors
	registry := NewRegistry()

	// Register a stale account detector manually for testing
	registry.Register(&testDetector{
		BaseDetector: NewBaseDetector("STALE_ACCOUNT", CategoryAccounts),
		findings: []types.Finding{{
			Type:     "STALE_ACCOUNT",
			Severity: types.SeverityHigh,
			Category: "accounts",
			Title:    "Stale Account",
			Count:    2,
		}},
	})

	provider := &testProvider{
		users: []types.User{
			{SAMAccountName: "active", LastLogon: time.Now()},
			{SAMAccountName: "stale1", LastLogon: time.Now().AddDate(-1, 0, 0)},
			{SAMAccountName: "stale2", LastLogon: time.Now().AddDate(-1, 0, 0)},
		},
	}

	engine := NewEngine(registry, provider)
	result, err := engine.Run(context.Background(), RunOptions{})
	require.NoError(t, err)

	assert.Len(t, result.Findings, 1)
	assert.Equal(t, "STALE_ACCOUNT", result.Findings[0].Type)
	assert.Equal(t, 2, result.Findings[0].Count)
}

// TestEngine_Run_ParallelExclusions_NoRace covers T_064/B_129: dataForDetector
// used to guard its ExclusionReport.PerDetector append with a mutex living on
// DetectorData, a struct value-copied by this same function — go vet's
// copylocks check flagged it. The lock now lives on *Engine, which every
// runParallel goroutine shares by pointer and which is never copied. Ten
// detectors each carry a per-detector exclusion rule that matches the same
// user, so all ten goroutines append to the shared PerDetector slice
// concurrently — run under `go test -race` this fails loudly if the
// synchronization is broken.
func TestEngine_Run_ParallelExclusions_NoRace(t *testing.T) {
	registry := NewRegistry()
	var cfgYAML strings.Builder
	cfgYAML.WriteString("version: 1\ndetectors:\n")
	for i := 0; i < 10; i++ {
		id := "RACE_" + string(rune('A'+i))
		registry.Register(&testDetector{
			BaseDetector: NewBaseDetector(id, CategoryAccounts),
		})
		cfgYAML.WriteString("  - id: " + id + "\n")
		cfgYAML.WriteString("    scope:\n      users:\n        sam_patterns: [\"svc-*\"]\n")
	}

	cfg, err := exclusions.LoadFromBytes([]byte(cfgYAML.String()))
	require.NoError(t, err)

	provider := &testProvider{
		users: []types.User{{SAMAccountName: "svc-target"}},
	}
	engine := NewEngine(registry, provider)

	result, err := engine.Run(context.Background(), RunOptions{
		Parallel:   true,
		Exclusions: cfg,
	})
	require.NoError(t, err)
	require.NotNil(t, result.Exclusions)
	assert.Len(t, result.Exclusions.PerDetector, 10, "every one of the 10 concurrent detectors should have recorded its own per-detector exclusion")
}
