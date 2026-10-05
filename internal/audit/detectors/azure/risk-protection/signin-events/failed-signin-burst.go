package signinevents

import (
	"context"
	"sort"
	"time"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// FailedSignInBurstDetector: isCredentialFailure (helpers.go, this package)
// scopes "failure" to sign-in error codes 50126 and 50056 - both documented
// Microsoft Entra STS error codes for invalid credentials, not connectivity
// or policy failures (Microsoft Learn, "Microsoft Entra authentication &
// authorization error codes", learn.microsoft.com/en-us/entra/
// identity-platform/reference-error-codes: AADSTS50126 "invalid username or
// password", AADSTS50056 "invalid or null password"). The sliding-window
// burst/spray logic itself is an etc-collector heuristic, not a named
// Microsoft detection, but the same technique (grouping invalid-credential
// failures by user or by source IP within a short window to distinguish
// targeted brute force from password spray) is standard published brute
// force/spray detection practice.
type FailedSignInBurstDetector struct {
	audit.BaseDetector
}

func NewFailedSignInBurstDetector() *FailedSignInBurstDetector {
	return &FailedSignInBurstDetector{BaseDetector: audit.NewBaseDetector(RISK_FAILED_SIGNIN_BURST, audit.CategoryRiskProtection)}
}

func (d *FailedSignInBurstDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	targeted := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityCritical,
		Category:    string(d.Category()),
		Title:       "Failed Sign-In Burst",
		Description: "A burst of invalid-credential sign-in failures indicates targeted brute force or password spray activity.",
		Count:       0,
		Details:     map[string]interface{}{"patternType": "targeted_bruteforce"},
	}
	spray := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityCritical,
		Category:    string(d.Category()),
		Title:       "Failed Sign-In Burst",
		Description: "A burst of invalid-credential sign-in failures from one IP across many users indicates password spray activity.",
		Count:       0,
		Details:     map[string]interface{}{"patternType": "password_spray"},
	}
	if len(data.AzureSignInLogs) == 0 {
		return []types.Finding{targeted, spray}
	}

	failures := make([]types.SignInLog, 0)
	for i := range data.AzureSignInLogs {
		if isCredentialFailure(&data.AzureSignInLogs[i]) {
			failures = append(failures, data.AzureSignInLogs[i])
		}
	}
	targeted.AffectedEntities = detectTargetedBruteforce(failures, data.IncludeDetails, &targeted.Count)
	spray.AffectedEntities = detectPasswordSpray(failures, data.IncludeDetails, &spray.Count)
	return []types.Finding{targeted, spray}
}

func init() {
	audit.MustRegister(NewFailedSignInBurstDetector())
}

func detectTargetedBruteforce(failures []types.SignInLog, includeDetails bool, count *int) []types.AffectedEntity {
	byUser := groupEventsByUser(failures)
	var affected []types.AffectedEntity
	for _, events := range byUser {
		sortEvents(events)
		type bestWindow struct {
			failures int
			start    time.Time
			end      time.Time
			ev       *types.SignInLog
			ips      []string
			codes    []int
		}
		var best bestWindow
		ipCounts := map[string]int{}
		codeCounts := map[int]int{}
		start := 0
		for end, ev := range events {
			if ev.IPAddress != "" {
				ipCounts[ev.IPAddress]++
			}
			codeCounts[ev.Status.ErrorCode]++
			for start <= end && ev.CreatedDateTime.Sub(events[start].CreatedDateTime) > failedBurstWindow {
				old := events[start]
				if old.IPAddress != "" {
					ipCounts[old.IPAddress]--
					if ipCounts[old.IPAddress] <= 0 {
						delete(ipCounts, old.IPAddress)
					}
				}
				codeCounts[old.Status.ErrorCode]--
				if codeCounts[old.Status.ErrorCode] <= 0 {
					delete(codeCounts, old.Status.ErrorCode)
				}
				start++
			}
			failureCount := end - start + 1
			if failureCount < failedBurstMinFailures || failureCount <= best.failures {
				continue
			}
			best = bestWindow{
				failures: failureCount,
				start:    events[start].CreatedDateTime,
				end:      ev.CreatedDateTime,
				ev:       ev,
				ips:      keysSorted(ipCounts),
				codes:    codesSortedFromCounts(codeCounts),
			}
		}
		if best.failures == 0 {
			continue
		}
		*count++
		if includeDetails {
			affected = append(affected, newUserRiskEntity(best.ev, map[string]any{
				"patternType":  "targeted_bruteforce",
				"failureCount": best.failures,
				"windowStart":  formatTime(best.start),
				"windowEnd":    formatTime(best.end),
				"sourceIps":    best.ips,
				"errorCodes":   best.codes,
			}))
		}
	}
	sortAffectedUsers(affected)
	return affected
}

func detectPasswordSpray(failures []types.SignInLog, includeDetails bool, count *int) []types.AffectedEntity {
	byIP := groupEventsByIP(failures)
	var affected []types.AffectedEntity
	for ip, events := range byIP {
		sortEvents(events)
		type bestWindow struct {
			failures      int
			distinctUsers int
			start         time.Time
			end           time.Time
			topTargets    []string
		}
		var best bestWindow
		userCounts := map[string]int{}
		start := 0
		for end, ev := range events {
			u := userDisplay(ev)
			userCounts[u]++
			for start <= end && ev.CreatedDateTime.Sub(events[start].CreatedDateTime) > failedBurstWindow {
				oldUser := userDisplay(events[start])
				userCounts[oldUser]--
				if userCounts[oldUser] <= 0 {
					delete(userCounts, oldUser)
				}
				start++
			}
			failureCount := end - start + 1
			distinctUsers := len(userCounts)
			if failureCount < failedBurstMinFailures || distinctUsers < failedBurstMinUsers {
				continue
			}
			if failureCount < best.failures || (failureCount == best.failures && distinctUsers <= best.distinctUsers) {
				continue
			}
			best = bestWindow{
				failures:      failureCount,
				distinctUsers: distinctUsers,
				start:         events[start].CreatedDateTime,
				end:           ev.CreatedDateTime,
				topTargets:    topTargets(userCounts, 10),
			}
		}
		if best.failures == 0 {
			continue
		}
		*count++
		if includeDetails {
			affected = append(affected, newIPRiskEntity(ip, map[string]any{
				"ipAddress":     ip,
				"patternType":   "password_spray",
				"failureCount":  best.failures,
				"distinctUsers": best.distinctUsers,
				"windowStart":   formatTime(best.start),
				"windowEnd":     formatTime(best.end),
				"topTargets":    best.topTargets,
			}))
		}
	}
	sort.Slice(affected, func(i, j int) bool { return affected[i].DN < affected[j].DN })
	return affected
}

func codesSortedFromCounts(m map[int]int) []int {
	out := make([]int, 0, len(m))
	for k, v := range m {
		if v > 0 {
			out = append(out, k)
		}
	}
	sort.Ints(out)
	return out
}
