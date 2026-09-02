package helpers

import (
	"fmt"
	"time"

	"github.com/etcsec-com/etc-collector/pkg/types"
)

// ToAffectedAppEntities converts AppRegistrations to affected entities
func ToAffectedAppEntities(apps []types.AppRegistration) []types.AffectedEntity {
	entities := make([]types.AffectedEntity, len(apps))
	for i := range apps {
		entities[i] = AppToAffectedEntity(&apps[i])
	}
	return entities
}

// ToAffectedServicePrincipalEntities converts ServicePrincipals to affected entities
func ToAffectedServicePrincipalEntities(sps []types.ServicePrincipal) []types.AffectedEntity {
	entities := make([]types.AffectedEntity, len(sps))
	for i := range sps {
		entities[i] = ServicePrincipalToAffectedEntity(&sps[i])
	}
	return entities
}

// ToAffectedRoleAssignmentEntities converts RoleAssignments to affected entities
func ToAffectedRoleAssignmentEntities(assignments []types.RoleAssignment) []types.AffectedEntity {
	entities := make([]types.AffectedEntity, len(assignments))
	for i := range assignments {
		entities[i] = RoleAssignmentToAffectedEntity(&assignments[i])
	}
	return entities
}

// ToAffectedCAPolicyEntities converts ConditionalAccessPolicies to affected entities
func ToAffectedCAPolicyEntities(policies []types.ConditionalAccessPolicy) []types.AffectedEntity {
	entities := make([]types.AffectedEntity, len(policies))
	for i := range policies {
		entities[i] = CAPolicyToAffectedEntity(&policies[i])
	}
	return entities
}

// ToAffectedRiskyUserEntities converts RiskyUsers to affected entities
func ToAffectedRiskyUserEntities(users []types.RiskyUser) []types.AffectedEntity {
	entities := make([]types.AffectedEntity, len(users))
	for i := range users {
		entities[i] = RiskyUserToAffectedEntity(&users[i])
	}
	return entities
}

// ToAffectedOAuth2GrantEntities converts OAuth2PermissionGrants to affected entities
func ToAffectedOAuth2GrantEntities(grants []types.OAuth2PermissionGrant) []types.AffectedEntity {
	entities := make([]types.AffectedEntity, len(grants))
	for i := range grants {
		entities[i] = OAuth2GrantToAffectedEntity(&grants[i])
	}
	return entities
}

// AppToAffectedEntity converts an AppRegistration to AffectedEntity
func AppToAffectedEntity(app *types.AppRegistration) types.AffectedEntity {
	// Check for expired credentials and find earliest expiry
	hasExpired := false
	var credentialExpiryDate *time.Time
	credentialCount := len(app.PasswordCredentials) + len(app.KeyCredentials)
	now := time.Now()

	checkCred := func(endDate time.Time) {
		if endDate.Before(now) {
			hasExpired = true
		}
		if !endDate.IsZero() && endDate.Year() > 2000 {
			if credentialExpiryDate == nil || endDate.Before(*credentialExpiryDate) {
				t := endDate
				credentialExpiryDate = &t
			}
		}
	}
	for _, cred := range app.PasswordCredentials {
		checkCred(cred.EndDate)
	}
	for _, cred := range app.KeyCredentials {
		checkCred(cred.EndDate)
	}

	// Extract dangerous permissions
	var dangerousPerms []string
	for _, resAccess := range app.RequiredResourceAccess {
		if resAccess.ResourceAppID == types.MicrosoftGraphAppID {
			for _, perm := range resAccess.Permissions {
				if perm.Type == "Role" { // Application permissions
					permName := perm.Name
					if permName == "" {
						// Fall back to GUID lookup
						if name, ok := types.GraphPermissionNames[perm.ID]; ok {
							permName = name
						}
					}
					if permName != "" {
						if _, isDangerous := types.DangerousGraphPermissions[permName]; isDangerous {
							dangerousPerms = append(dangerousPerms, permName)
						}
					}
				}
			}
		}
	}

	// Build human-readable API permissions list
	apiPerms := app.ApiPermissions
	if len(apiPerms) == 0 {
		// Fallback: resolve from RequiredResourceAccess
		for _, resAccess := range app.RequiredResourceAccess {
			for _, perm := range resAccess.Permissions {
				if perm.Name != "" {
					apiPerms = append(apiPerms, perm.Name)
				} else if name, ok := types.GraphPermissionNames[perm.ID]; ok {
					apiPerms = append(apiPerms, name)
				}
			}
		}
	}

	ownerCount := len(app.Owners)

	azureFields := &types.AzureEntityFields{
		AppId:                 &app.AppID,
		SignInAudience:        &app.SignInAudience,
		HasExpiredCredentials: &hasExpired,
		DangerousPermissions:  dangerousPerms,
		ApiPermissions:        apiPerms,
		ImplicitGrantEnabled:  &app.ImplicitGrantEnabled,
		CredentialCount:       &credentialCount,
		PublisherDomain:       app.PublisherDomain,
		Homepage:              app.Homepage,
		LogoutUrl:             app.LogoutUrl,
		Owners:                app.Owners,
		AppOwnerCount:         &ownerCount,
	}
	if credentialExpiryDate != nil {
		azureFields.CredentialExpiryDate = credentialExpiryDate
	}
	if !app.CreatedDateTime.IsZero() {
		azureFields.CreatedDateTime = &app.CreatedDateTime
	}
	if app.LastSignInDateTime != nil {
		azureFields.AppLastSignInDateTime = app.LastSignInDateTime
	}

	return types.AffectedEntity{
		Type:        "application",
		DN:          app.ID,
		Name:        app.DisplayName,
		DisplayName: app.DisplayName,
		Azure:       azureFields,
	}
}

// ServicePrincipalToAffectedEntity converts a ServicePrincipal to AffectedEntity
func ServicePrincipalToAffectedEntity(sp *types.ServicePrincipal) types.AffectedEntity {
	// Check for expired credentials and find earliest expiry
	hasExpired := false
	var credentialExpiryDate *time.Time
	credentialCount := len(sp.PasswordCredentials) + len(sp.KeyCredentials)
	now := time.Now()

	checkCred := func(endDate time.Time) {
		if endDate.Before(now) {
			hasExpired = true
		}
		if !endDate.IsZero() && endDate.Year() > 2000 {
			if credentialExpiryDate == nil || endDate.Before(*credentialExpiryDate) {
				t := endDate
				credentialExpiryDate = &t
			}
		}
	}
	for _, cred := range sp.PasswordCredentials {
		checkCred(cred.EndDate)
	}
	for _, cred := range sp.KeyCredentials {
		checkCred(cred.EndDate)
	}

	// Determine if first-party (Microsoft-owned)
	isFirstParty := sp.AppOwnerOrganizationID != "" &&
		(sp.AppOwnerOrganizationID == "f8cdef31-a31e-4b4a-93e4-5f571e91255a" || // Microsoft Services
			sp.AppOwnerOrganizationID == "72f988bf-86f1-41af-91ab-2d7cd011db47") // Microsoft Corporation

	ownerCount := len(sp.Owners)

	azureFields := &types.AzureEntityFields{
		ServicePrincipalType:      &sp.ServicePrincipalType,
		IsFirstParty:              &isFirstParty,
		AppId:                     &sp.AppID,
		AppOwnerOrganizationId:    &sp.AppOwnerOrganizationID,
		AccountEnabled:            &sp.AccountEnabled,
		HasExpiredCredentials:     &hasExpired,
		CredentialCount:           &credentialCount,
		AppRoleAssignmentRequired: sp.AppRoleAssignmentRequired,
		Owners:                    sp.Owners,
		AppOwnerCount:             &ownerCount,
	}
	if credentialExpiryDate != nil {
		azureFields.CredentialExpiryDate = credentialExpiryDate
	}
	if sp.CreatedDateTime != nil {
		azureFields.CreatedDateTime = sp.CreatedDateTime
	}
	if sp.LastSignInDateTime != nil {
		azureFields.AppLastSignInDateTime = sp.LastSignInDateTime
	}

	return types.AffectedEntity{
		Type:        "servicePrincipal",
		DN:          sp.ID,
		Name:        sp.DisplayName,
		DisplayName: sp.DisplayName,
		Enabled:     sp.AccountEnabled,
		Azure:       azureFields,
	}
}

// RoleAssignmentToAffectedEntity converts a RoleAssignment to AffectedEntity
func RoleAssignmentToAffectedEntity(ra *types.RoleAssignment) types.AffectedEntity {
	name := ra.RoleName
	if name == "" {
		name = ra.RoleID
	}

	scope := ra.DirectoryScopeID
	if scope == "" {
		scope = "/"
	}

	assignType := ra.AssignmentType
	if assignType == "" {
		if ra.IsPermanent {
			assignType = "direct"
		} else {
			assignType = "eligible"
		}
	}

	// Build description with enriched fields
	var desc string
	if ra.PrincipalName != "" && ra.UserPrincipalName != "" {
		desc = fmt.Sprintf("Principal: %s (%s) [%s]", ra.PrincipalName, ra.UserPrincipalName, assignType)
	} else if ra.PrincipalName != "" {
		desc = fmt.Sprintf("Principal: %s [%s]", ra.PrincipalName, assignType)
	} else {
		desc = fmt.Sprintf("Principal: %s [%s]", ra.PrincipalID, assignType)
	}

	azureFields := &types.AzureEntityFields{
		RoleName:         &ra.RoleName,
		RoleDefinitionId: &ra.RoleID,
		PrincipalType:    &ra.PrincipalType,
		IsPermanent:      &ra.IsPermanent,
		AssignmentScope:  &scope,
		// PIM fields
		AssignmentType:        stringPtr(assignType),
		MemberType:            stringPtr(ra.MemberType),
		ActivationDuration:    stringPtr(ra.ActivationDuration),
		Justification:         stringPtr(ra.Justification),
		TicketInfo:            stringPtr(ra.TicketInfo),
		IsEligible:            boolPtr(ra.IsEligible),
		RequiresJustification: boolPtr(ra.RequiresJustification),
		RequiresApproval:      boolPtr(ra.RequiresApproval),
	}

	// Principal identity enrichment
	if ra.UserPrincipalName != "" {
		azureFields.PrincipalUpn = &ra.UserPrincipalName
	}
	if ra.Mail != "" {
		azureFields.PrincipalMail = &ra.Mail
	}
	if ra.PrincipalJobTitle != "" {
		azureFields.PrincipalJobTitle = &ra.PrincipalJobTitle
	}
	if ra.PrincipalDepartment != "" {
		azureFields.PrincipalDepartment = &ra.PrincipalDepartment
	}
	if !ra.StartDateTime.IsZero() {
		t := ra.StartDateTime
		azureFields.ActivatedAt = &t
	}
	if !ra.EndDateTime.IsZero() {
		t := ra.EndDateTime
		azureFields.ExpirationDateTime = &t
	}

	return types.AffectedEntity{
		Type:        "roleAssignment",
		DN:          ra.PrincipalID,
		Name:        name,
		DisplayName: ra.PrincipalName,
		Description: desc,
		Azure:       azureFields,
	}
}

// Helper functions for pointer conversion
func stringPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func boolPtr(b bool) *bool {
	if !b {
		return nil
	}
	return &b
}

// CAPolicyToAffectedEntity converts a ConditionalAccessPolicy to AffectedEntity
func CAPolicyToAffectedEntity(p *types.ConditionalAccessPolicy) types.AffectedEntity {
	// Build conditions summary
	conditionsSummary := fmt.Sprintf("Users: %d included, %d excluded | Apps: %d included",
		len(p.IncludeUsers), len(p.ExcludeUsers), len(p.IncludeApps))

	return types.AffectedEntity{
		Type:        "conditionalAccessPolicy",
		DN:          p.ID,
		Name:        p.DisplayName,
		DisplayName: p.DisplayName,
		Description: fmt.Sprintf("State: %s", p.State),
		Azure: &types.AzureEntityFields{
			State:            &p.State,
			Conditions:       &conditionsSummary,
			GrantControls:    p.GrantControls,
			UserRiskLevels:   p.UserRiskLevels,
			SignInRiskLevels: p.SignInRiskLevels,
			IncludeUsers:     p.IncludeUsers,
			ExcludeUsers:     p.ExcludeUsers,
			IncludeApps:      p.IncludeApps,
		},
	}
}

// RiskyUserToAffectedEntity converts a RiskyUser to AffectedEntity
func RiskyUserToAffectedEntity(ru *types.RiskyUser) types.AffectedEntity {
	return types.AffectedEntity{
		Type:              "user",
		DN:                ru.ID,
		SAMAccountName:    ru.UserPrincipalName,
		UserPrincipalName: ru.UserPrincipalName,
		DisplayName:       ru.UserDisplayName,
		Description:       fmt.Sprintf("Risk: %s (%s)", ru.RiskLevel, ru.RiskState),
		Azure: &types.AzureEntityFields{
			RiskLevel: &ru.RiskLevel,
			RiskState: &ru.RiskState,
		},
	}
}

// OAuth2GrantToAffectedEntity converts an OAuth2PermissionGrant to AffectedEntity
func OAuth2GrantToAffectedEntity(g *types.OAuth2PermissionGrant) types.AffectedEntity {
	name := g.ClientName
	if name == "" {
		name = g.ClientID
	}

	permCategory := "Delegated"

	azureFields := &types.AzureEntityFields{
		ConsentType:        &g.ConsentType,
		Scope:              &g.Scope,
		PermissionCategory: &permCategory,
	}
	if g.ResourceName != "" {
		azureFields.ResourceName = &g.ResourceName
	}
	if g.ClientAppID != "" {
		azureFields.ClientAppId = &g.ClientAppID
	}

	// Build enriched description
	var desc string
	if g.ClientName != "" && g.ResourceName != "" {
		desc = fmt.Sprintf("Consent granted to '%s' for %s on %s", g.ClientName, g.Scope, g.ResourceName)
	} else {
		desc = fmt.Sprintf("Consent: %s, Scope: %s", g.ConsentType, g.Scope)
	}

	return types.AffectedEntity{
		Type:        "oauth2Grant",
		DN:          g.ID,
		Name:        name,
		DisplayName: g.ClientName,
		Description: desc,
		Azure:       azureFields,
	}
}
