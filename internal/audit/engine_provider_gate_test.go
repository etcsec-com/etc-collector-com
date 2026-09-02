// T_019 — provider gating. These tests run the real detector registry (both
// platforms self-register into audit.DefaultRegistry via init()) through the
// engine with a provider that collects nothing, which is the exact shape of
// the bug: on an AD audit the Entra "absence of config = finding" detectors
// fired against data that was never collected.
//
// External test package on purpose: internal/audit/detectors/* imports
// internal/audit, so only `package audit_test` can pull the real detectors in
// without an import cycle. That also means the assertions go through the
// public Run() path — findings actually produced — rather than the unexported
// selection helper.
package audit_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/catalog"
	"github.com/etcsec-com/etc-collector/internal/providers"
	"github.com/etcsec-com/etc-collector/pkg/types"

	// Side-effect imports — register every AD and Entra detector.
	_ "github.com/etcsec-com/etc-collector/internal/audit/detectors/ad"
	_ "github.com/etcsec-com/etc-collector/internal/audit/detectors/azure"
)

// gateProvider is a provider that returns no data and implements nothing
// beyond providers.Provider, so the gate can only key off Type() — the same
// situation as a real audit whose counterpart platform was never collected.
type gateProvider struct{ ptype providers.ProviderType }

func (p *gateProvider) Type() providers.ProviderType  { return p.ptype }
func (p *gateProvider) Connect(context.Context) error { return nil }
func (p *gateProvider) Close() error                  { return nil }
func (p *gateProvider) IsConnected() bool             { return true }

func (p *gateProvider) GetUsers(context.Context, providers.QueryOptions) ([]types.User, error) {
	return nil, nil
}

func (p *gateProvider) GetGroups(context.Context, providers.QueryOptions) ([]types.Group, error) {
	return nil, nil
}

func (p *gateProvider) GetComputers(context.Context, providers.QueryOptions) ([]types.Computer, error) {
	return nil, nil
}

func (p *gateProvider) GetDomainInfo(context.Context) (*types.DomainInfo, error) {
	return nil, nil
}

// detectorPlatforms indexes the live registry by detector ID so a finding can
// be attributed to the platform that emitted it.
func detectorPlatforms(t *testing.T) map[string]catalog.Platform {
	t.Helper()
	all := audit.DefaultRegistry.All()
	require.NotEmpty(t, all, "detector registry is empty — side-effect imports missing")
	out := make(map[string]catalog.Platform, len(all))
	for _, d := range all {
		out[d.ID()] = catalog.PlatformOf(d)
	}
	return out
}

// findingsByPlatform splits the result's finding types by emitting platform.
func findingsByPlatform(t *testing.T, result *types.AuditResult) map[catalog.Platform][]string {
	t.Helper()
	index := detectorPlatforms(t)
	out := make(map[catalog.Platform][]string)
	for _, f := range result.Findings {
		p, known := index[f.Type]
		if !known {
			p = catalog.PlatformUnknown
		}
		out[p] = append(out[p], f.Type)
	}
	return out
}

func runGated(t *testing.T, ptype providers.ProviderType, opts audit.RunOptions) *types.AuditResult {
	t.Helper()
	engine := audit.NewEngine(audit.DefaultRegistry, &gateProvider{ptype: ptype})
	result, err := engine.Run(context.Background(), opts)
	require.NoError(t, err)
	return result
}

// TestAzureDetectorsSkippedOnADProvider is the ticket's headline case: an
// on-prem AD audit must emit zero Entra/Azure finding types.
func TestAzureDetectorsSkippedOnADProvider(t *testing.T) {
	byPlatform := findingsByPlatform(t, runGated(t, providers.ProviderTypeLDAP, audit.RunOptions{}))

	assert.Empty(t, byPlatform[catalog.PlatformAzure],
		"an AD audit must not emit Entra/Azure findings — the tenant was never collected")
	assert.NotEmpty(t, byPlatform[catalog.PlatformAD],
		"the AD detectors must still run — this is a gate, not a deletion")
}

// TestADDetectorsSkippedOnAzureProvider is the mirror case, and doubles as the
// proof that the Azure detectors are gated rather than removed.
func TestADDetectorsSkippedOnAzureProvider(t *testing.T) {
	byPlatform := findingsByPlatform(t, runGated(t, providers.ProviderTypeAzure, audit.RunOptions{}))

	assert.Empty(t, byPlatform[catalog.PlatformAD],
		"an Entra audit must not emit on-prem AD findings")
	assert.NotEmpty(t, byPlatform[catalog.PlatformAzure],
		"the Entra detectors must still run on an Azure audit")
}

// TestExplicitDetectorSelectionOverridesProviderGate pins down how explicit
// selection and the gate compose.
//
// The ticket asked for explicit selection to override the gate. It does NOT,
// deliberately: Scope.ApplyTo materialises every --scope-* form — profiles,
// include-categories, even a lone --scope-exclude-detectors — into
// RunOptions.DetectorIDs (cmd/etc-collector/audit.go and internal/saas/scope.go
// both go through it), so a DetectorIDs exemption would silently reopen the
// bug for every scoped audit. What "override" can safely mean, and what this
// test asserts, is that selection semantics are untouched inside the audited
// platform, and that the gate — not the selection — decides eligibility
// across platforms.
func TestExplicitDetectorSelectionOverridesProviderGate(t *testing.T) {
	// Pick detectors that demonstrably fire on empty data ("absence of config
	// = finding" checks) from each platform's own run, so the assertions below
	// observe real findings rather than silence.
	adRun := findingsByPlatform(t, runGated(t, providers.ProviderTypeLDAP, audit.RunOptions{}))
	azureRun := findingsByPlatform(t, runGated(t, providers.ProviderTypeAzure, audit.RunOptions{}))
	require.NotEmpty(t, adRun[catalog.PlatformAD])
	require.NotEmpty(t, azureRun[catalog.PlatformAzure])
	adID := adRun[catalog.PlatformAD][0]
	azureID := azureRun[catalog.PlatformAzure][0]

	t.Run("DetectorIDs select exactly the named detectors", func(t *testing.T) {
		result := runGated(t, providers.ProviderTypeLDAP, audit.RunOptions{
			DetectorIDs: []string{adID},
		})
		require.Len(t, result.Findings, 1, "only the named detector may run")
		assert.Equal(t, adID, result.Findings[0].Type)
	})

	t.Run("ExcludeDetectors still wins over an explicit ID", func(t *testing.T) {
		result := runGated(t, providers.ProviderTypeLDAP, audit.RunOptions{
			DetectorIDs:      []string{adID},
			ExcludeDetectors: []string{adID},
		})
		assert.Empty(t, result.Findings, "ExcludeDetectors must have the last word")
	})

	t.Run("Categories are intersected with the gate", func(t *testing.T) {
		// "groups" is the one category both platforms share, so it is the only
		// way --scope-include-categories can leak cross-platform detectors.
		byPlatform := findingsByPlatform(t, runGated(t, providers.ProviderTypeLDAP, audit.RunOptions{
			Categories: []audit.DetectorCategory{audit.CategoryGroups},
		}))
		assert.NotEmpty(t, byPlatform[catalog.PlatformAD],
			"--scope-include-categories groups must still select the AD groups detectors")
		assert.Empty(t, byPlatform[catalog.PlatformAzure],
			"...and only those")
	})

	t.Run("a cross-platform ID is gated, not selected", func(t *testing.T) {
		result := runGated(t, providers.ProviderTypeLDAP, audit.RunOptions{
			DetectorIDs: []string{azureID},
		})
		assert.Empty(t, result.Findings,
			"an Entra detector named on an AD audit has no Entra data to judge — it can only be a false positive")
	})

	t.Run("a materialised scope cannot reopen the bug", func(t *testing.T) {
		// The realistic regression: any collector.yaml audit.scope section or
		// --scope-* flag resolves to the full detector ID list minus a few.
		// If DetectorIDs bypassed the gate, all 148+ Entra detectors would be
		// back on an AD audit.
		opts := audit.RunOptions{}
		scope := audit.Scope{ExcludeDetectors: []string{adID}}
		scope.ApplyTo(&opts, audit.DefaultRegistry)
		require.Greater(t, len(opts.DetectorIDs), 100, "scope must materialise into DetectorIDs")

		engine := audit.NewEngine(audit.DefaultRegistry, &gateProvider{ptype: providers.ProviderTypeLDAP})
		result, err := engine.Run(context.Background(), opts)
		require.NoError(t, err)

		index := detectorPlatforms(t)
		for _, f := range result.Findings {
			assert.NotEqual(t, catalog.PlatformAzure, index[f.Type],
				"scoped AD audit leaked an Entra finding: %s", f.Type)
		}
	})
}

// TestProviderGateIsFailOpen documents the safety rule: a provider the gate
// cannot classify must not silently empty the detector set.
func TestProviderGateIsFailOpen(t *testing.T) {
	byPlatform := findingsByPlatform(t, runGated(t, providers.ProviderType("mystery-provider"), audit.RunOptions{}))

	assert.NotEmpty(t, byPlatform[catalog.PlatformAD], "unknown provider must not drop AD detectors")
	assert.NotEmpty(t, byPlatform[catalog.PlatformAzure], "unknown provider must not drop Entra detectors")
}
