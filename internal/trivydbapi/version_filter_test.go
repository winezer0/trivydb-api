package trivydbapi

import (
	"testing"

	dbtypes "github.com/aquasecurity/trivy-db/pkg/types"
)

func TestAdvisoryAffectsVersion(t *testing.T) {
	advisory := dbtypes.Advisory{VulnerableVersions: []string{"<4.17.21"}}
	if !advisoryAffectsVersion("npm::", "4.17.20", advisory) {
		t.Fatal("expected vulnerable version to match")
	}
	if advisoryAffectsVersion("npm::", "4.17.21", advisory) {
		t.Fatal("fixed version must not match vulnerable range")
	}
	advisory.Status = dbtypes.StatusNotAffected
	if advisoryAffectsVersion("npm::", "4.17.20", advisory) {
		t.Fatal("not-affected advisory must be excluded")
	}
}

func TestSourceMatchesPURLType(t *testing.T) {
	for _, test := range []struct {
		source string
		typeID string
		want   bool
	}{
		{source: "npm::", typeID: "npm", want: true},
		{source: "debian:12", typeID: "deb", want: true},
		{source: "alpine:3.22", typeID: "apk", want: true},
		{source: "pypi::", typeID: "npm", want: false},
	} {
		if got := sourceMatchesPURLType(test.source, test.typeID); got != test.want {
			t.Errorf("sourceMatchesPURLType(%q, %q) = %t, want %t", test.source, test.typeID, got, test.want)
		}
	}
}
