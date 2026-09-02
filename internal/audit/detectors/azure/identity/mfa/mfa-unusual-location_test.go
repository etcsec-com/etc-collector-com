package mfa

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

func TestMFAUnusual_AllInsideNamedLocation(t *testing.T) {
	d := NewMFAUnusualLocationDetector()
	data := &audit.DetectorData{
		AzureNamedLocations: []types.NamedLocation{
			{DisplayName: "EU", CountriesAndRegions: []string{"FR", "DE"}},
		},
		AzureRiskySignIns: []types.RiskySignIn{
			{UserPrincipalName: "a@t", Location: "FR", RiskLevel: "medium", RiskState: "atRisk"},
		},
	}
	f := d.Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("expected 0, got %d", f.Count)
	}
}

func TestMFAUnusual_OutsideNamedLocation(t *testing.T) {
	d := NewMFAUnusualLocationDetector()
	data := &audit.DetectorData{
		AzureNamedLocations: []types.NamedLocation{
			{DisplayName: "EU", CountriesAndRegions: []string{"FR", "DE"}},
		},
		AzureRiskySignIns: []types.RiskySignIn{
			{UserPrincipalName: "a@t", Location: "RU", RiskLevel: "medium", RiskState: "atRisk"},
		},
	}
	f := d.Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("expected 1, got %d", f.Count)
	}
	if f.Severity != types.SeverityMedium {
		t.Fatalf("expected medium, got %s", f.Severity)
	}
}

func TestMFAUnusual_NoNamedLocationsFallback(t *testing.T) {
	d := NewMFAUnusualLocationDetector()
	data := &audit.DetectorData{
		AzureRiskySignIns: []types.RiskySignIn{
			{UserPrincipalName: "a@t", Location: "FR", RiskLevel: "high", RiskState: "atRisk"},
			{UserPrincipalName: "b@t", Location: "FR", RiskLevel: "low", RiskState: "atRisk"},
		},
	}
	f := d.Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("expected 1 (high-risk only), got %d", f.Count)
	}
}

func TestMFAUnusual_DismissedIgnored(t *testing.T) {
	d := NewMFAUnusualLocationDetector()
	data := &audit.DetectorData{
		AzureNamedLocations: []types.NamedLocation{
			{DisplayName: "EU", CountriesAndRegions: []string{"FR"}},
		},
		AzureRiskySignIns: []types.RiskySignIn{
			{UserPrincipalName: "a@t", Location: "RU", RiskLevel: "high", RiskState: "dismissed"},
		},
	}
	f := d.Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("expected 0 for dismissed, got %d", f.Count)
	}
}
