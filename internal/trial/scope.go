package trial

import "github.com/etcsec-com/etc-collector/internal/audit"

// applyScopeFromParams reads `params.scope` from a trial command and applies it
// to the engine RunOptions. Returns warnings for unknown profile / category /
// detector ID. Same payload shape as the SaaS daemon — see saas/scope.go.
func applyScopeFromParams(params map[string]interface{}, opts *audit.RunOptions) []string {
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
	return scope.ApplyTo(opts, audit.DefaultRegistry)
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
