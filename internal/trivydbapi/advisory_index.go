package trivydbapi

import (
	"encoding/json"
	"strings"

	trivydb "github.com/aquasecurity/trivy-db/pkg/db"
	dbtypes "github.com/aquasecurity/trivy-db/pkg/types"
	bolt "go.etcd.io/bbolt"
)

func findAliasAdvisories(identifier string) (map[string][]dbtypes.Advisory, error) {
	conn := trivydb.Config{}.Connection()
	matches := make(map[string][]dbtypes.Advisory)
	identifier = strings.ToUpper(identifier)
	err := conn.View(func(tx *bolt.Tx) error {
		return tx.ForEach(func(_ []byte, root *bolt.Bucket) error {
			if root == nil {
				return nil
			}
			return root.ForEach(func(packageKey, packageValue []byte) error {
				if packageValue != nil {
					return nil
				}
				packageBucket := root.Bucket(packageKey)
				if packageBucket == nil {
					return nil
				}
				return packageBucket.ForEach(func(vulnerabilityKey, raw []byte) error {
					if raw == nil {
						return nil
					}
					var advisory dbtypes.Advisory
					if err := json.Unmarshal(raw, &advisory); err != nil || len(advisory.VendorIDs) == 0 {
						return nil
					}
					if !matchesID(identifier, advisory) {
						return nil
					}
					advisory.VulnerabilityID = string(vulnerabilityKey)
					matches[advisory.VulnerabilityID] = append(matches[advisory.VulnerabilityID], advisory)
					return nil
				})
			})
		})
	})
	return matches, err
}

func matchesID(identifier string, advisory dbtypes.Advisory) bool {
	identifier = strings.ToUpper(strings.TrimSpace(identifier))
	if strings.EqualFold(advisory.VulnerabilityID, identifier) {
		return true
	}
	for _, alias := range advisory.VendorIDs {
		if strings.EqualFold(alias, identifier) {
			return true
		}
	}
	return false
}

func appendUnique(values []string, candidates ...string) []string {
	seen := make(map[string]struct{}, len(values)+len(candidates))
	for _, value := range values {
		seen[value] = struct{}{}
	}
	for _, value := range candidates {
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		values = append(values, value)
	}
	return values
}
