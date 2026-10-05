package saml

import (
	"context"
	"testing"
	"time"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

func TestSAML_LongLifetime(t *testing.T) {
	d := NewSAMLCertLongLifetimeDetector()
	data := &audit.DetectorData{
		Now: time.Now(),
		AzureServicePrincipals: []types.ServicePrincipal{
			buildSP("sp1", "Sign", time.Now().Add(4*365*24*time.Hour)),
		},
	}
	f := d.Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("expected 1 long lifetime, got %d", f.Count)
	}
}

// TestSAML_NativeThreeYearDefaultNotFlagged reproduces the ecart: Microsoft
// Entra ID's own SAML SSO configuration flow issues certificates valid for up
// to 3 years by default (Microsoft Learn, "Certificate signing options in a
// SAML token" - "Microsoft Entra ID configures a certificate to expire after
// three years when it is created automatically during SAML single sign-on
// configuration"). Before the fix, the 2-year limit flagged such a
// brand-new, platform-issued certificate as "excessive" the moment it was
// created, with zero abnormal configuration involved.
func TestSAML_NativeThreeYearDefaultNotFlagged(t *testing.T) {
	d := NewSAMLCertLongLifetimeDetector()
	now := time.Now()
	data := &audit.DetectorData{
		Now: now,
		AzureServicePrincipals: []types.ServicePrincipal{
			buildSP("sp1", "Sign", now.Add(3*365*24*time.Hour)),
		},
	}
	f := d.Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("expected 0: a certificate at Entra's own native 3-year default must not be flagged as excessive, got %d", f.Count)
	}
}

func TestSAML_HealthyCertNotLongLifetime(t *testing.T) {
	d := NewSAMLCertLongLifetimeDetector()
	data := &audit.DetectorData{
		Now: time.Now(),
		AzureServicePrincipals: []types.ServicePrincipal{
			buildSP("sp1", "Sign", time.Now().Add(180*24*time.Hour)), // 6 months
		},
	}
	if d.Detect(context.Background(), data)[0].Count != 0 {
		t.Fatalf("long should be 0")
	}
}
