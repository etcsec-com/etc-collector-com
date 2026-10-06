package access

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// GUEST_TO_GUEST_INVITE tested strings.Contains(policy, "guest"), which
// matches "adminsAndGuestInviters" and "adminsGuestInvitersAndAllMembers"
// (guests CANNOT invite under either) and never matches "everyone" (the
// only Graph value where guests actually can, and the tenant default) - an
// inverted signal, not a missing-data bug.

func detectGuestInvite(policy string) types.Finding {
	d := NewGuestToGuestInviteDetector()
	data := &audit.DetectorData{AzureTenantConfig: &types.AzureTenantConfig{GuestInvitationPolicy: policy}}
	return d.Detect(context.Background(), data)[0]
}

func TestGuestToGuestInvite_RestrictedPoliciesDoNotTrigger(t *testing.T) {
	for _, policy := range []string{"none", "adminsAndGuestInviters", "adminsGuestInvitersAndAllMembers"} {
		if f := detectGuestInvite(policy); f.Count != 0 {
			t.Errorf("policy=%q: expected 0 (guests cannot invite), got %d", policy, f.Count)
		}
	}
}

func TestGuestToGuestInvite_EveryoneTriggersFinding(t *testing.T) {
	if f := detectGuestInvite("everyone"); f.Count != 1 {
		t.Fatalf("policy=\"everyone\": expected 1 (guests can invite), got %d", f.Count)
	}
}

func TestGuestToGuestInvite_EmptyPolicyDoesNotGuess(t *testing.T) {
	if f := detectGuestInvite(""); f.Count != 0 {
		t.Fatalf("empty policy (unread): expected 0, got %d", f.Count)
	}
}
