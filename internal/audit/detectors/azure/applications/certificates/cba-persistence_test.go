package certificates

import (
	"context"
	"testing"
	"time"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

func TestCBA_NoCertificates(t *testing.T) {
	d := NewCBAPersistenceDetector()
	data := &audit.DetectorData{
		Now: time.Now(),
		AzureAppRegistrations: []types.AppRegistration{
			{DisplayName: "app1"},
		},
	}
	f := d.Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("expected 0, got %d", f.Count)
	}
}

func TestCBA_ExpiredCertificate(t *testing.T) {
	d := NewCBAPersistenceDetector()
	data := &audit.DetectorData{
		Now: time.Now(),
		AzureAppRegistrations: []types.AppRegistration{
			{DisplayName: "app1", KeyCredentials: []types.AppCredential{
				{Type: "certificate", EndDate: time.Now().Add(-24 * time.Hour)},
			}},
		},
	}
	f := d.Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("expected 0 for expired cert, got %d", f.Count)
	}
}

func TestCBA_ActiveCertificateOnApp(t *testing.T) {
	d := NewCBAPersistenceDetector()
	data := &audit.DetectorData{
		Now: time.Now(),
		AzureAppRegistrations: []types.AppRegistration{
			{DisplayName: "app1", KeyCredentials: []types.AppCredential{
				{Type: "certificate", Thumbprint: "ABC", EndDate: time.Now().Add(30 * 24 * time.Hour)},
			}},
		},
		IncludeDetails: true,
	}
	f := d.Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("expected 1 for active cert, got %d", f.Count)
	}
	if f.Severity != types.SeverityHigh {
		t.Fatalf("expected severity high, got %s", f.Severity)
	}
}

func TestCBA_ActiveCertificateOnServicePrincipal(t *testing.T) {
	d := NewCBAPersistenceDetector()
	data := &audit.DetectorData{
		Now: time.Now(),
		AzureServicePrincipals: []types.ServicePrincipal{
			{DisplayName: "sp1", KeyCredentials: []types.AppCredential{
				{Type: "certificate", Thumbprint: "DEF", EndDate: time.Now().Add(90 * 24 * time.Hour)},
			}},
		},
	}
	f := d.Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("expected 1 for SP cert, got %d", f.Count)
	}
}

func TestCBA_Mixed(t *testing.T) {
	d := NewCBAPersistenceDetector()
	data := &audit.DetectorData{
		Now: time.Now(),
		AzureAppRegistrations: []types.AppRegistration{
			{DisplayName: "app1", KeyCredentials: []types.AppCredential{
				{Type: "certificate", EndDate: time.Now().Add(30 * 24 * time.Hour)},
			}},
			{DisplayName: "app2", KeyCredentials: []types.AppCredential{
				{Type: "certificate", EndDate: time.Now().Add(-1 * time.Hour)}, // expired, should not count
			}},
		},
		AzureServicePrincipals: []types.ServicePrincipal{
			{DisplayName: "sp1", KeyCredentials: []types.AppCredential{
				{Type: "certificate", EndDate: time.Now().Add(365 * 24 * time.Hour)},
			}},
		},
	}
	f := d.Detect(context.Background(), data)[0]
	if f.Count != 2 {
		t.Fatalf("expected 2 (app1 + sp1), got %d", f.Count)
	}
}

func TestCBA_PasswordCredentialIgnored(t *testing.T) {
	d := NewCBAPersistenceDetector()
	data := &audit.DetectorData{
		Now: time.Now(),
		AzureAppRegistrations: []types.AppRegistration{
			{DisplayName: "app1", PasswordCredentials: []types.AppCredential{
				{Type: "password", EndDate: time.Now().Add(30 * 24 * time.Hour)},
			}},
		},
	}
	f := d.Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("expected 0 (password, not cert), got %d", f.Count)
	}
}
