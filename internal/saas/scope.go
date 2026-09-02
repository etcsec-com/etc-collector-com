package saas

import "github.com/etcsec-com/etc-collector/internal/audit"

// applyScopeFromParams reads `params.scope` (object) from a SaaS command and
// applies it to the engine RunOptions. Returns warnings (unknown profile /
// category / detector ID) for the daemon to log + surface in result.warnings.
//
// Expected payload shape:
//
//	"params": {
//	  "scope": {
//	    "profile": "quick",
//	    "includeCategories": ["kerberos","permissions"],
//	    "excludeCategories": ["network"],
//	    "includeDetectors": ["AD_KERBEROS_AS_REP_ROASTING"],
//	    "excludeDetectors": ["AD_GPO_LLMNR_ENABLED"]
//	  }
//	}
//
// Missing or non-object `scope` → no-op.
func applyScopeFromParams(params map[string]interface{}, opts *audit.RunOptions, reg *audit.Registry) []string {
	raw, ok := params["scope"].(map[string]interface{})
	if !ok || raw == nil {
		return nil
	}
	scope := audit.Scope{}
	if v, ok := raw["profile"].(string); ok {
		scope.Profile = v
	}
	scope.IncludeCategories = toCategories(stringSlice(raw["includeCategories"]))
	scope.ExcludeCategories = toCategories(stringSlice(raw["excludeCategories"]))
	scope.IncludeDetectors = stringSlice(raw["includeDetectors"])
	scope.ExcludeDetectors = stringSlice(raw["excludeDetectors"])
	return scope.ApplyTo(opts, reg)
}

func stringSlice(v interface{}) []string {
	arr, ok := v.([]interface{})
	if !ok {
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, item := range arr {
		if s, ok := item.(string); ok && s != "" {
			out = append(out, s)
		}
	}
	return out
}

func toCategories(values []string) []audit.DetectorCategory {
	if len(values) == 0 {
		return nil
	}
	out := make([]audit.DetectorCategory, 0, len(values))
	for _, v := range values {
		out = append(out, audit.DetectorCategory(v))
	}
	return out
}
