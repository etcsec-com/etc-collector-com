package mfa

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

const (
	IDNoPasswordless       = "MFA_NO_PASSWORDLESS"
	CategoryNoPasswordless = audit.CategoryIdentity
)

// NoPasswordlessDetector checks if passwordless authentication is enabled
type NoPasswordlessDetector struct {
	audit.BaseDetector
}

// NewMfaNoPasswordlessDetector creates a new no passwordless detector
func NewMfaNoPasswordlessDetector() *NoPasswordlessDetector {
	return &NoPasswordlessDetector{
		BaseDetector: audit.NewBaseDetector(IDNoPasswordless, CategoryNoPasswordless),
	}
}

// Detect checks if FIDO2 (inherently passwordless) or Microsoft Authenticator
// (which can run in push-only, passwordless-only, or "any" mode) is enabled
// as a passwordless-capable method.
//
// FIDO2 is unambiguous: state=="enabled" always means passwordless
// capability, so - as with MFA_NO_FIDO2 - this checks includeTargets for
// all_users coverage rather than trusting the tenant-level toggle alone.
//
// Microsoft Authenticator is not unambiguous. Per-includeTarget-group,
// Microsoft Graph exposes an authenticationMode field (any | push |
// deviceBasedPush, where deviceBasedPush is "passwordless only" -
// learn.microsoft.com/en-us/graph/api/resources/
// microsoftauthenticatorauthenticationmethodtarget) that determines whether
// a group can actually use passwordless phone sign-in or only classic push
// MFA. That field is not on types.AuthMethodTarget (out of this detector's
// scope to add - needs a types.go + client.go change), so this
// detector cannot currently distinguish "Authenticator enabled for push
// only" from "Authenticator enabled for passwordless". Enabled Authenticator
// is treated as a possible-but-unconfirmed passwordless signal (non vu on
// mode), not a proven one - the description says so explicitly.
func (d *NoPasswordlessDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	finding := types.Finding{
		Type:     IDNoPasswordless,
		Severity: types.SeverityMedium,
		Category: string(CategoryNoPasswordless),
		Title:    "Passwordless Authentication Not Confirmed",
		Description: "Neither FIDO2 (covering all users) nor Microsoft Authenticator is enabled. " +
			"Passwordless methods eliminate password-based attack vectors. Note: an enabled " +
			"Microsoft Authenticator method is not proof of passwordless capability - its " +
			"per-group authentication mode (push-only vs. passwordless) is not currently " +
			"collected, so this treats 'enabled' as a possible signal, not a confirmed one.",
		Count: 0,
	}

	if data.AzureAuthMethodsPolicy == nil {
		return []types.Finding{finding}
	}

	fido2 := data.AzureAuthMethodsPolicy.FIDO2
	fido2CoversAllUsers := fido2.State == "enabled"
	if fido2CoversAllUsers {
		fido2CoversAllUsers = false
		for _, target := range fido2.IncludeTargets {
			if target.ID == allUsersTargetID {
				fido2CoversAllUsers = true
				break
			}
		}
	}
	authenticatorEnabled := data.AzureAuthMethodsPolicy.MicrosoftAuthenticator.State == "enabled"

	if !fido2CoversAllUsers && !authenticatorEnabled {
		finding.Count = 1
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewMfaNoPasswordlessDetector())
}
