// Package types — Azure authorization + consent policies (v3.1.37).
//
// These shapes mirror /v1.0/policies/authorizationPolicy and
// /v1.0/policies/adminConsentRequestPolicy and are used by the baseline
// security mode check (audit.baselineSecurity) to evaluate user-consent
// gates, app/tenant creation gates, and guest-invite restrictions.

package types

// AuthorizationPolicy mirrors Graph /policies/authorizationPolicy. The
// fields kept here are the ones the baseline security checks consume —
// the full Graph response carries a few more legacy flags
// (blockMsolPowerShell, allowedToSignUpEmailBasedSubscriptions, etc.) that
// we currently don't map.
type AuthorizationPolicy struct {
	ID                                        string                               `json:"id,omitempty"`
	DisplayName                               string                               `json:"displayName,omitempty"`
	Description                               string                               `json:"description,omitempty"`
	AllowInvitesFrom                          string                               `json:"allowInvitesFrom,omitempty"`             // everyone | adminsAndGuestInviters | adminsOnly | none
	AllowUserConsentForRiskyApps              *bool                                `json:"allowUserConsentForRiskyApps,omitempty"` // pointer so absence ≠ false
	AllowEmailVerifiedUsersToJoinOrganization *bool                                `json:"allowEmailVerifiedUsersToJoinOrganization,omitempty"`
	GuestUserRoleID                           string                               `json:"guestUserRoleId,omitempty"`
	DefaultUserRolePermissions                *AuthorizationDefaultUserPermissions `json:"defaultUserRolePermissions,omitempty"`
}

// AuthorizationDefaultUserPermissions captures the gates Microsoft applies to
// the "default user role" — the implicit role every standard user inherits.
// Each *bool is a pointer because absence is meaningful (couldn't read the
// field) vs explicit false (admin disabled it).
type AuthorizationDefaultUserPermissions struct {
	AllowedToCreateApps                      *bool    `json:"allowedToCreateApps,omitempty"`
	AllowedToCreateSecurityGroups            *bool    `json:"allowedToCreateSecurityGroups,omitempty"`
	AllowedToCreateTenants                   *bool    `json:"allowedToCreateTenants,omitempty"`
	AllowedToReadBitlockerKeysForOwnedDevice *bool    `json:"allowedToReadBitlockerKeysForOwnedDevice,omitempty"`
	AllowedToReadOtherUsers                  *bool    `json:"allowedToReadOtherUsers,omitempty"`
	PermissionGrantPoliciesAssigned          []string `json:"permissionGrantPoliciesAssigned,omitempty"`
}

// AdminConsentRequestPolicy mirrors Graph /policies/adminConsentRequestPolicy.
// IsEnabled toggles the "request admin consent" workflow shown to users when
// they hit a permission gate. NotifyReviewers + RemindersEnabled drive the
// notification cadence to the assigned reviewers.
type AdminConsentRequestPolicy struct {
	IsEnabled             *bool                         `json:"isEnabled,omitempty"`
	NotifyReviewers       *bool                         `json:"notifyReviewers,omitempty"`
	RemindersEnabled      *bool                         `json:"remindersEnabled,omitempty"`
	RequestDurationInDays int                           `json:"requestDurationInDays,omitempty"`
	Version               int                           `json:"version,omitempty"`
	Reviewers             []AdminConsentRequestReviewer `json:"reviewers,omitempty"`
}

type AdminConsentRequestReviewer struct {
	Query     string `json:"query,omitempty"`     // /v1.0/users/<id> | /v1.0/groups/<id> | /v1.0/roleManagement/...
	QueryType string `json:"queryType,omitempty"` // MicrosoftGraph
	QueryRoot string `json:"queryRoot,omitempty"`
}
