// Package config imports all configuration-related detectors.
package config

import (
	_ "github.com/etcsec-com/etc-collector/internal/audit/detectors/azure/config/security"
	_ "github.com/etcsec-com/etc-collector/internal/audit/detectors/azure/config/settings"
)

// config/logging (AZ_AUDIT_LOG_RETENTION_SHORT, AZ_DIAGNOSTIC_SETTINGS_MISSING,
// AZ_NO_SIEM_EXPORT, AZ_SIGN_IN_LOGS_NOT_RETAINED) was removed in T_058
// (B_158): all four fired unconditionally on every tenant, and none had a
// real Graph signal behind them to fix instead. Diagnostic settings / log
// export configuration for Entra ID lives under Azure Resource Manager
// (/providers/microsoft.aadiam/diagnosticSettings), a different API audience
// (management.azure.com) than the Graph-only scope this collector currently
// authenticates with — confirmed live: a Graph access token gets HTTP 401
// against that endpoint. Re-add these only alongside real ARM collection.
