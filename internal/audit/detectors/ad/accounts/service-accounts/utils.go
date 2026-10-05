package serviceaccounts

import (
	"regexp"

	"github.com/etcsec-com/etc-collector/pkg/types"
)

var serviceAccountPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)^svc[_-]`),
	regexp.MustCompile(`(?i)[_-]svc$`),
	regexp.MustCompile(`(?i)^sa[_-]`),
	regexp.MustCompile(`(?i)[_-]sa$`),
	regexp.MustCompile(`(?i)service`),
	regexp.MustCompile(`(?i)^sql`),
	regexp.MustCompile(`(?i)^iis`),
	regexp.MustCompile(`(?i)^app`),
}

// isServiceAccount checks if a user is a service account
func isServiceAccount(u types.User) bool {
	// Has SPN = definitely a service account
	if len(u.ServicePrincipalNames) > 0 {
		return true
	}

	// Matches naming pattern
	for _, pattern := range serviceAccountPatterns {
		if pattern.MatchString(u.SAMAccountName) {
			return true
		}
	}

	return false
}
