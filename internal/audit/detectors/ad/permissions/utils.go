// Package permissions contains permission-related security detectors
package permissions

import "github.com/etcsec-com/etc-collector/pkg/types"

// GetUniqueObjects returns unique object DNs from ACL entries
func GetUniqueObjects(entries []types.ACLEntry) []string {
	seen := make(map[string]bool)
	var result []string

	for _, ace := range entries {
		if !seen[ace.ObjectDN] {
			seen[ace.ObjectDN] = true
			result = append(result, ace.ObjectDN)
		}
	}

	return result
}
