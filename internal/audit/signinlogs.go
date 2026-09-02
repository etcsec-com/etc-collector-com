package audit

import (
	"net"
	"sort"
	"strings"

	"github.com/etcsec-com/etc-collector/pkg/types"
)

// AnonymizeSignInIPs masks the last octet of every IPv4 address to "0".
// IPv6 addresses are left untouched — the "last octet" mapping is not
// meaningful there and the SaaS analyzers don't need it for the GDPR
// use case (lab/demo audits).
//
// Mutates the input slice in place; no return value because every call site
// already owns the slice.
func AnonymizeSignInIPs(logs []types.SignInLog) {
	for i := range logs {
		ip := strings.TrimSpace(logs[i].IPAddress)
		if ip == "" {
			continue
		}
		parsed := net.ParseIP(ip)
		if parsed == nil {
			continue
		}
		v4 := parsed.To4()
		if v4 == nil {
			continue // IPv6 — left unchanged
		}
		logs[i].IPAddress = (net.IPv4(v4[0], v4[1], v4[2], 0)).String()
	}
}

// AggregateSignInLogs collapses raw events into the SignInLogsAggregated
// summary. Use only when mode=aggregated; mode=raw must keep the full event
// stream for SaaS-side correlation (impossible travel, push fatigue, etc.).
//
// Bucket sizes are not capped except where the spec says so:
//   - RiskySignIns is the full subset (riskState != "" and riskState != "none")
//   - TopUsersByVolume is capped at 50 (per spec)
//   - TopServicePrincipals carries up to 50 SPs, each with at most 100
//     raw events (per spec, for ConsentFix detection)
func AggregateSignInLogs(logs []types.SignInLog) *types.SignInLogsAggregated {
	if logs == nil {
		return &types.SignInLogsAggregated{}
	}

	out := &types.SignInLogsAggregated{Total: len(logs)}

	clientApp := map[string]int{}
	authProto := map[string]int{}
	country := map[string]int{}
	signInTypeBucket := map[string]int{}
	userVolume := map[string]*types.SignInUserVolume{}
	spVolume := map[string]*spAcc{}

	for i := range logs {
		ev := &logs[i]

		// Status counters — Graph reports success as errorCode == 0.
		if ev.Status != nil && ev.Status.ErrorCode == 0 {
			out.SuccessCount++
		} else if ev.Status != nil {
			out.FailureCount++
		}

		// MFA: at least one auth detail with a non-password method that succeeded.
		if anyMFA(ev.AuthenticationDetails) {
			out.MFACount++
		}

		// Legacy auth = Other clients per Microsoft's classification.
		if isLegacyClientApp(ev.ClientAppUsed) {
			out.LegacyAuthCount++
		}

		if strings.EqualFold(ev.AuthenticationProtocol, "deviceCode") {
			out.DeviceCodeCount++
		}
		if ev.CrossTenantAccessType != "" && !strings.EqualFold(ev.CrossTenantAccessType, "none") {
			out.CrossTenantCount++
		}
		if strings.EqualFold(ev.UserType, "Guest") {
			out.GuestCount++
		}

		bumpBucket(clientApp, ev.ClientAppUsed)
		bumpBucket(authProto, ev.AuthenticationProtocol)
		if ev.Location != nil {
			bumpBucket(country, ev.Location.CountryOrRegion)
		}
		// signInEventTypes is a slice — a single event can carry multiple
		// types, so each one bumps its own bucket.
		for _, t := range ev.SignInEventTypes {
			bumpBucket(signInTypeBucket, t)
		}

		// Risky subset: anything other than empty/none.
		if ev.RiskState != "" && !strings.EqualFold(ev.RiskState, "none") {
			out.RiskySignIns = append(out.RiskySignIns, *ev)
		}

		// Per-user volume.
		if ev.UserPrincipalName != "" {
			u := userVolume[ev.UserPrincipalName]
			if u == nil {
				u = &types.SignInUserVolume{
					UserPrincipalName: ev.UserPrincipalName,
					UserDisplayName:   ev.UserDisplayName,
				}
				userVolume[ev.UserPrincipalName] = u
			}
			u.Count++
		}

		// Per-SP roll-up — only servicePrincipal/managedIdentity flows count
		// (interactiveUser sign-ins use an app but represent a human action
		// and would dominate the bucket otherwise).
		if hasSPEventType(ev.SignInEventTypes) && ev.AppID != "" {
			sp := spVolume[ev.AppID]
			if sp == nil {
				sp = &spAcc{
					AppID:          ev.AppID,
					AppDisplayName: ev.AppDisplayName,
				}
				spVolume[ev.AppID] = sp
			}
			sp.Count++
			sp.LastEvents = append(sp.LastEvents, *ev)
			if len(sp.LastEvents) > spLastEventsCap {
				// Keep the last N (sliding window — drop oldest).
				sp.LastEvents = sp.LastEvents[len(sp.LastEvents)-spLastEventsCap:]
			}
		}
	}

	out.ByClientApp = bucketsSorted(clientApp)
	out.ByAuthProtocol = bucketsSorted(authProto)
	out.ByCountry = bucketsSorted(country)
	out.BySignInType = bucketsSorted(signInTypeBucket)
	out.TopUsersByVolume = topUsers(userVolume, topUsersCap)
	out.TopServicePrincipals = topSPs(spVolume, topSPsCap)
	return out
}

const (
	topUsersCap     = 50
	topSPsCap       = 50
	spLastEventsCap = 100
)

type spAcc struct {
	AppID          string
	AppDisplayName string
	Count          int
	LastEvents     []types.SignInLog
}

func bumpBucket(m map[string]int, k string) {
	if k == "" {
		return
	}
	m[k]++
}

func bucketsSorted(m map[string]int) []types.SignInBucket {
	if len(m) == 0 {
		return nil
	}
	out := make([]types.SignInBucket, 0, len(m))
	for k, v := range m {
		out = append(out, types.SignInBucket{Key: k, Count: v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Key < out[j].Key
	})
	return out
}

func topUsers(m map[string]*types.SignInUserVolume, cap int) []types.SignInUserVolume {
	if len(m) == 0 {
		return nil
	}
	out := make([]types.SignInUserVolume, 0, len(m))
	for _, v := range m {
		out = append(out, *v)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].UserPrincipalName < out[j].UserPrincipalName
	})
	if len(out) > cap {
		out = out[:cap]
	}
	return out
}

func topSPs(m map[string]*spAcc, cap int) []types.SignInSPVolume {
	if len(m) == 0 {
		return nil
	}
	out := make([]types.SignInSPVolume, 0, len(m))
	for _, v := range m {
		out = append(out, types.SignInSPVolume{
			AppID:          v.AppID,
			AppDisplayName: v.AppDisplayName,
			Count:          v.Count,
			LastEvents:     v.LastEvents,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].AppID < out[j].AppID
	})
	if len(out) > cap {
		out = out[:cap]
	}
	return out
}

// anyMFA reports whether at least one authentication step succeeded with a
// method other than "Password" — heuristic for "this sign-in actually used
// MFA". Graph distinguishes "Password" (single factor) vs everything else.
func anyMFA(details []types.SignInAuthDetail) bool {
	for _, d := range details {
		if !d.Succeeded {
			continue
		}
		if d.AuthenticationMethod == "" || strings.EqualFold(d.AuthenticationMethod, "Password") {
			continue
		}
		return true
	}
	return false
}

// isLegacyClientApp follows Microsoft's "legacy auth" classification:
// anything not explicitly modern is legacy. Concretely, the "Other clients"
// label is the catch-all for legacy protocols (IMAP, POP, SMTP, ActiveSync,
// MAPI, AutoDiscover, OAB, EWS).
func isLegacyClientApp(s string) bool {
	switch strings.ToLower(s) {
	case "other clients",
		"authenticated smtp",
		"exchange activesync",
		"imap",
		"pop",
		"mapi over http",
		"offline address book",
		"outlook anywhere (rpc over http)",
		"exchange web services",
		"autodiscover":
		return true
	}
	return false
}

func hasSPEventType(types []string) bool {
	for _, t := range types {
		switch strings.ToLower(t) {
		case "serviceprincipal", "managedidentity":
			return true
		}
	}
	return false
}
