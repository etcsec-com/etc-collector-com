package sspr

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

func TestSsprNotRequiredAdmins_AllAdminsSSPREnabled(t *testing.T) {
	d := NewSsprNotRequiredAdminsDetector()
	data := &audit.DetectorData{
		AzureAuthMethodsDetail: &types.AuthMethodsDetail{
			UserRegistrationStats: &types.UserRegistrationStats{
				AdminUsers: types.AdminRegistrationStats{Total: 2, SSPRRegistered: 2},
			},
		},
	}
	f := d.Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("expected 0 (all admins SSPR-registered), got %d", f.Count)
	}
}

func TestSsprNotRequiredAdmins_SomeAdminMissingSSPR(t *testing.T) {
	d := NewSsprNotRequiredAdminsDetector()
	data := &audit.DetectorData{
		AzureAuthMethodsDetail: &types.AuthMethodsDetail{
			UserRegistrationStats: &types.UserRegistrationStats{
				AdminUsers: types.AdminRegistrationStats{Total: 2, SSPRRegistered: 1},
			},
		},
	}
	f := d.Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("expected 1 (an admin lacks SSPR), got %d", f.Count)
	}
}

func TestSsprNotRequiredAdmins_NoDataCollected(t *testing.T) {
	d := NewSsprNotRequiredAdminsDetector()
	data := &audit.DetectorData{}
	f := d.Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("expected 0 (no data -> no guess), got %d", f.Count)
	}
}

func TestSsprNotRequiredAdmins_NoAdmins(t *testing.T) {
	d := NewSsprNotRequiredAdminsDetector()
	data := &audit.DetectorData{
		AzureAuthMethodsDetail: &types.AuthMethodsDetail{
			UserRegistrationStats: &types.UserRegistrationStats{},
		},
	}
	f := d.Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("expected 0 (no admin users in tenant), got %d", f.Count)
	}
}
