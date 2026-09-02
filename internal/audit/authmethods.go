package audit

import "github.com/etcsec-com/etc-collector/pkg/types"

// BuildAuthMethodsDetail composes the per-method policy, the strength
// policies bucket, and the per-user registration stats into the single
// audit.authenticationMethodsDetail payload.
//
// Returns nil when all three sources are empty/nil so the JSON output
// skips the audit.authenticationMethodsDetail key entirely (omitempty).
func BuildAuthMethodsDetail(
	policy *types.AuthMethodsPolicy,
	strengths []types.AuthStrengthPolicy,
	userRegs []types.UserRegistrationDetail,
) *types.AuthMethodsDetail {
	var out types.AuthMethodsDetail
	if policy != nil {
		out.Policy = policy
	}
	if len(strengths) > 0 {
		out.StrengthPolicies = summarizeStrengths(strengths)
	}
	if len(userRegs) > 0 {
		out.UserRegistrationStats = aggregateUserRegistrations(userRegs)
	}
	if out.Policy == nil && out.StrengthPolicies == nil && out.UserRegistrationStats == nil {
		return nil
	}
	return &out
}

// summarizeStrengths splits the slice into builtIn vs custom.
func summarizeStrengths(strengths []types.AuthStrengthPolicy) *types.AuthStrengthSummary {
	out := &types.AuthStrengthSummary{Total: len(strengths)}
	for _, s := range strengths {
		if s.PolicyType == "builtIn" {
			out.BuiltIn = append(out.BuiltIn, s)
		} else {
			out.Custom = append(out.Custom, s)
		}
	}
	return out
}

// aggregateUserRegistrations turns the per-user detail slice into the
// summary counters + per-method bucket + admin sub-stat. The per-user
// slice itself is NOT exposed in the JSON output (volume cap on big
// tenants).
func aggregateUserRegistrations(userRegs []types.UserRegistrationDetail) *types.UserRegistrationStats {
	out := &types.UserRegistrationStats{
		Total:    len(userRegs),
		ByMethod: map[string]int{},
	}
	for _, u := range userRegs {
		if u.IsMFACapable {
			out.MFACapable++
		}
		if u.IsMFARegistered {
			out.MFARegistered++
		}
		if u.IsPasswordlessCapable {
			out.PasswordlessCapable++
		}
		hasFIDO2 := false
		for _, m := range u.MethodsRegistered {
			out.ByMethod[m]++
			if m == "fido2" {
				hasFIDO2 = true
			}
		}
		if hasFIDO2 {
			out.FIDO2Registered++
		}
		if u.IsAdmin {
			out.AdminUsers.Total++
			if u.IsMFACapable {
				out.AdminUsers.MFACapable++
			}
			if u.IsMFARegistered {
				out.AdminUsers.MFARegistered++
			}
			if hasFIDO2 {
				out.AdminUsers.FIDO2Registered++
			}
		}
	}
	return out
}
