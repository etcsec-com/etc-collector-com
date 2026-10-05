// Consent enforced at the COLLECTION layer.
//
// The detector-selection gate is not enough on its own: selection runs after
// collectData, so by the time it decides what to analyse, everything has
// already been read. A collector that reads what the operator refused is
// indefensible whatever it does with the result afterwards - so the refusal
// has to stop the read itself.
//
// These tests assert exactly that, on the one capability that has a real
// provider today (SYSVOL): a refusal means the provider is never called, and
// the audit says so out loud instead of silently returning less.
package audit_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/providers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// consentProvider returns just enough domain information for collectData to
// reach the SYSVOL block: without a DomainDN that block is skipped for an
// unrelated reason, and the test would pass without proving anything.
type consentProvider struct{}

func (p *consentProvider) Type() providers.ProviderType  { return providers.ProviderTypeLDAP }
func (p *consentProvider) Connect(context.Context) error { return nil }
func (p *consentProvider) Close() error                  { return nil }
func (p *consentProvider) IsConnected() bool             { return true }

func (p *consentProvider) GetUsers(context.Context, providers.QueryOptions) ([]types.User, error) {
	return nil, nil
}

func (p *consentProvider) GetGroups(context.Context, providers.QueryOptions) ([]types.Group, error) {
	return nil, nil
}

func (p *consentProvider) GetComputers(context.Context, providers.QueryOptions) ([]types.Computer, error) {
	return nil, nil
}

func (p *consentProvider) GetDomainInfo(context.Context) (*types.DomainInfo, error) {
	return &types.DomainInfo{DomainName: "example", DomainDN: "DC=example,DC=com"}, nil
}

// spySYSVOL records whether the SYSVOL share was touched at all. It asserts
// reach, not output: the question is whether the collector went to the share
// after being told not to, and any call at all is already the failure.
type spySYSVOL struct{ called bool }

func (s *spySYSVOL) CollectGPOPolicies([]types.GPO, string) map[string]*audit.GPOPolicy {
	s.called = true
	return nil
}

func (s *spySYSVOL) ScanSYSVOL([]types.GPO, string) []audit.SYSVOLFinding {
	s.called = true
	return nil
}

func runWithSYSVOL(t *testing.T, opts audit.RunOptions) (*types.AuditResult, *spySYSVOL) {
	t.Helper()
	engine := audit.NewEngine(audit.DefaultRegistry, &consentProvider{})
	spy := &spySYSVOL{}
	engine.SetSYSVOLProvider(spy)
	result, err := engine.Run(context.Background(), opts)
	require.NoError(t, err)
	return result, spy
}

// The control: with no refusal, the provider IS reached. Without this case the
// refusal test would pass even if the SYSVOL block had simply stopped working,
// and would prove nothing about consent.
func TestCollectionConsent_SysvolReachedWhenNotRefused(t *testing.T) {
	_, spy := runWithSYSVOL(t, audit.RunOptions{})
	assert.True(t, spy.called,
		"SYSVOL provider was not reached even with no refusal - the refusal test below would be vacuous")
}

// The barrier itself: a refused capability is never exercised.
func TestCollectionConsent_RefusedSysvolIsNeverRead(t *testing.T) {
	result, spy := runWithSYSVOL(t, audit.RunOptions{
		DeniedCapabilities: []audit.Capability{audit.CapSysvol},
	})

	assert.False(t, spy.called,
		"the operator refused SYSVOL and the collector read it anyway - consent that does not stop collection is not consent")

	var announced bool
	for _, w := range result.Warnings {
		if w.Code == "CAPABILITY_REFUSED_SYSVOL" {
			announced = true
		}
	}
	assert.True(t, announced,
		"SYSVOL was skipped without saying so - a Group Policy detector finding nothing because nothing was read "+
			"must not look like one finding nothing because there was nothing to find")
}

// The second half of the mechanism: a detector whose verdict is built
// entirely from SYSVOL-parsed data must not run at all once SYSVOL is
// refused - not run on empty data and report a finding that reads like a
// real measurement of a clean environment.
func TestCollectionConsent_RefusedSysvolExcludesDependentDetectors(t *testing.T) {
	ids := audit.SysvolDependentDetectors()
	require.NotEmpty(t, ids,
		"detectorCapability is empty - this test would pass vacuously and prove nothing about exclusion; "+
			"populate it with the detectors whose verdict depends entirely on SYSVOL")

	result, _ := runWithSYSVOL(t, audit.RunOptions{
		DeniedCapabilities: []audit.Capability{audit.CapSysvol},
	})

	sysvolOnly := make(map[string]bool, len(ids))
	for _, id := range ids {
		sysvolOnly[id] = true
	}
	for _, f := range result.Findings {
		assert.False(t, sysvolOnly[f.Type],
			"detector %s produced a finding despite SYSVOL being refused - it is listed in detectorCapability "+
				"as fully SYSVOL-dependent and must have been excluded from selection, not run on empty data", f.Type)
	}

	var warning *types.Warning
	for i := range result.Warnings {
		if result.Warnings[i].Code == "CAPABILITY_REFUSED_SYSVOL" {
			warning = &result.Warnings[i]
		}
	}
	require.NotNil(t, warning, "CAPABILITY_REFUSED_SYSVOL warning missing")
	assert.NotEmpty(t, warning.AffectedDetectors,
		"the warning must name which detectors were excluded, not just that something was refused")
	for _, id := range ids {
		assert.Contains(t, warning.AffectedDetectors, id,
			"%s is SYSVOL-dependent but is not named in AffectedDetectors", id)
	}
}

// Non-regression: with nothing refused, a SYSVOL-dependent detector still
// runs exactly as before detectorCapability was populated. WDIGEST_ENABLED
// is representative of the group: its own logic treats "no GPO configures
// this" as a violation (Count=1), which fires here even against the spy's
// empty data - the point is not whether the finding is correct, only that
// the detector was invoked at all, proving selection is unchanged when
// nothing was refused.
func TestCollectionConsent_UnaffectedWhenNotRefused(t *testing.T) {
	result, _ := runWithSYSVOL(t, audit.RunOptions{})

	var found bool
	for _, f := range result.Findings {
		if f.Type == "WDIGEST_ENABLED" {
			found = true
		}
	}
	assert.True(t, found,
		"WDIGEST_ENABLED did not run with no capability refused - populating detectorCapability must not "+
			"change detector selection when nothing was refused")

	for _, w := range result.Warnings {
		assert.NotEqual(t, "CAPABILITY_REFUSED_SYSVOL", w.Code,
			"the refusal warning must not appear when nothing was refused")
	}
}

// A refusal outranks a grant, whatever order the two lists are given in.
// Otherwise a configuration could re-enable, by accident, something the
// operator had explicitly ruled out.
func TestCollectionConsent_RefusalOutranksGrant(t *testing.T) {
	_, spy := runWithSYSVOL(t, audit.RunOptions{
		GrantedCapabilities: []audit.Capability{audit.CapSysvol},
		DeniedCapabilities:  []audit.Capability{audit.CapSysvol},
	})
	assert.False(t, spy.called,
		"a grant overrode an explicit refusal - refusal must always win")
}

// The refusal must be announced even when NO provider was wired at all.
//
// This is the case the other tests could not see, because they all wire a spy
// provider. Once the refusal also stopped the CLI from connecting to the share,
// the provider was nil on a real run - and the warning, which was guarded on
// the provider being present, vanished. The audit dropped the dependent
// findings and said nothing about why, which is exactly the silence this whole
// mechanism exists to prevent. Caught on a real domain controller, not here.
func TestCollectionConsent_RefusalAnnouncedWithoutAnyProvider(t *testing.T) {
	engine := audit.NewEngine(audit.DefaultRegistry, &consentProvider{})
	// Deliberately NO SetSYSVOLProvider: this is what a real run looks like
	// once the refusal has stopped the connection upstream.
	result, err := engine.Run(context.Background(), audit.RunOptions{
		DeniedCapabilities: []audit.Capability{audit.CapSysvol},
	})
	require.NoError(t, err)

	var announced bool
	for _, w := range result.Warnings {
		if w.Code == "CAPABILITY_REFUSED_SYSVOL" {
			announced = true
		}
	}
	assert.True(t, announced,
		"the capability was refused and no provider was wired, and the audit said nothing - "+
			"a refusal that leaves no trace in the report reads exactly like a clean result")
}
