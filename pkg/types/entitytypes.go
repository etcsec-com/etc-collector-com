package types

// Canonical entity type strings used in AffectedEntity.Type. Keeping them as
// constants prevents the casing/spelling drift that produced both
// "cert-template" and "certTemplate" (and "dnszone" vs "dnsZone") before
// v3.1.28.
const (
	EntityTypeUser                    = "user"
	EntityTypeGroup                   = "group"
	EntityTypeComputer                = "computer"
	EntityTypeOU                      = "ou"
	EntityTypeGPO                     = "gpo"
	EntityTypeCertTemplate            = "certTemplate"
	EntityTypeDNSZone                 = "dnsZone"
	EntityTypeDomain                  = "domain"
	EntityTypeSite                    = "site"
	EntityTypeTrust                   = "trust"
	EntityTypePrincipal               = "principal"
	EntityTypeWellKnownSid            = "wellKnownSid"
	EntityTypeDC                      = "dc"
	EntityTypeACLEntry                = "aclEntry"
	EntityTypeConfig                  = "config"
	EntityTypeGap                     = "gap"
	EntityTypeTenant                  = "tenant"
	EntityTypeApplication             = "application"
	EntityTypeServicePrincipal        = "servicePrincipal"
	EntityTypeConditionalAccessPolicy = "conditionalAccessPolicy"
	EntityTypeDirectoryRole           = "directoryRole"
	EntityTypeRoleAssignment          = "roleAssignment"
	EntityTypeOAuth2Grant             = "oauth2Grant"
	EntityTypeRiskDetection           = "riskDetection"
)
