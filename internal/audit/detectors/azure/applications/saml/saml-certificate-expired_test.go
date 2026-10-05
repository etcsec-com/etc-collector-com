package saml

import (
	"context"
	"testing"
	"time"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

func TestSAML_Expired(t *testing.T) {
	d := NewSAMLCertExpiredDetector()
	data := &audit.DetectorData{
		Now: time.Now(),
		AzureServicePrincipals: []types.ServicePrincipal{
			buildSP("sp1", "Sign", time.Now().Add(-48*time.Hour)),
		},
	}
	f := d.Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("expected 1 expired, got %d", f.Count)
	}
	if f.Severity != types.SeverityCritical {
		t.Fatalf("expected critical, got %s", f.Severity)
	}
}

func TestSAML_NonSigningUsageIgnored(t *testing.T) {
	d := NewSAMLCertExpiredDetector()
	data := &audit.DetectorData{
		Now: time.Now(),
		AzureServicePrincipals: []types.ServicePrincipal{
			buildSP("sp1", "Encrypt", time.Now().Add(-48*time.Hour)),
		},
	}
	f := d.Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("expected 0 for non-signing usage, got %d", f.Count)
	}
}

// this detector used to compare a collected EndDate against time.Now()
// independently. It now reads data.Now, matching the other two SAML checks
// (see saml-certificate-expiring-soon_test.go's replay test).
func TestSAML_HealthyCertNotExpired(t *testing.T) {
	d := NewSAMLCertExpiredDetector()
	data := &audit.DetectorData{
		Now: time.Now(),
		AzureServicePrincipals: []types.ServicePrincipal{
			buildSP("sp1", "Sign", time.Now().Add(180*24*time.Hour)), // 6 months
		},
	}
	if d.Detect(context.Background(), data)[0].Count != 0 {
		t.Fatalf("expired should be 0")
	}
}
