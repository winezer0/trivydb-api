package trivydbapi

import (
	"strings"

	gem "github.com/aquasecurity/go-gem-version"
	npm "github.com/aquasecurity/go-npm-version/pkg"
	pep440 "github.com/aquasecurity/go-pep440-version"
	"github.com/aquasecurity/go-version/pkg/semver"
	"github.com/aquasecurity/go-version/pkg/version"
	dbtypes "github.com/aquasecurity/trivy-db/pkg/types"
	mvn "github.com/masahiro331/go-mvn-version"
)

func sourceEcosystem(source string) string {
	source = strings.ToLower(strings.TrimSpace(source))
	if strings.HasSuffix(source, "::") {
		source = strings.TrimSuffix(source, "::")
	}
	if index := strings.IndexByte(source, ':'); index >= 0 {
		source = source[:index]
	}
	switch source {
	case "gem":
		return "rubygems"
	case "golang":
		return "go"
	case "cargo":
		return "crates.io"
	default:
		return source
	}
}

func sourceMatchesPURLType(source, purlType string) bool {
	ecosystem := sourceEcosystem(source)
	switch strings.ToLower(strings.TrimSpace(purlType)) {
	case "generic":
		return true
	case "golang":
		return ecosystem == "go"
	case "cargo":
		return ecosystem == "crates.io"
	case "gem":
		return ecosystem == "rubygems"
	case "composer":
		return ecosystem == "packagist"
	case "apk":
		return ecosystem == "alpine"
	case "deb":
		return ecosystem == "debian" || ecosystem == "ubuntu"
	case "rpm":
		switch ecosystem {
		case "redhat", "rocky", "alma", "oracle", "amazon", "suse", "photon", "mariner", "azurelinux", "wolfi", "chainguard":
			return true
		default:
			return false
		}
	default:
		return ecosystem == sourceEcosystem(purlType)
	}
}

func advisoryAffectsVersion(source, queryVersion string, advisory dbtypes.Advisory) bool {
	if advisory.Status == dbtypes.StatusNotAffected {
		return false
	}
	ecosystem := sourceEcosystem(source)
	for _, constraint := range advisory.UnaffectedVersions {
		if matches, err := versionConstraintMatches(ecosystem, queryVersion, constraint); err == nil && matches {
			return false
		}
	}

	constraints := advisory.VulnerableVersions
	if len(constraints) == 0 && advisory.AffectedVersion != "" {
		constraints = []string{"=" + advisory.AffectedVersion}
	}
	if len(constraints) > 0 {
		for _, constraint := range constraints {
			if matches, err := versionConstraintMatches(ecosystem, queryVersion, constraint); err != nil || matches {
				// Preserve possible findings when an ecosystem constraint cannot be parsed.
				return true
			}
		}
		return false
	}
	if advisory.FixedVersion == "" {
		return true
	}
	for _, fixed := range strings.Split(advisory.FixedVersion, ",") {
		if matches, err := versionConstraintMatches(ecosystem, queryVersion, "< "+strings.TrimSpace(fixed)); err != nil || matches {
			return true
		}
	}
	return false
}

func versionConstraintMatches(ecosystem, queryVersion, expression string) (bool, error) {
	expression = strings.TrimSpace(expression)
	if expression == "" {
		return true, nil
	}
	if !strings.ContainsAny(expression, "<>=!~^,*") {
		expression = "=" + expression
	}
	for _, alternative := range strings.Split(expression, "||") {
		match, err := versionConstraintGroupMatches(ecosystem, queryVersion, strings.TrimSpace(alternative))
		if err != nil {
			return false, err
		}
		if match {
			return true, nil
		}
	}
	return false, nil
}

func versionConstraintGroupMatches(ecosystem, queryVersion, expression string) (bool, error) {
	switch ecosystem {
	case "npm":
		constraints, err := npm.NewConstraints(expression)
		if err != nil {
			return false, err
		}
		v, err := npm.NewVersion(queryVersion)
		if err != nil {
			return false, err
		}
		return constraints.Check(v), nil
	case "rubygems":
		constraints, err := gem.NewConstraints(expression)
		if err != nil {
			return false, err
		}
		v, err := gem.NewVersion(queryVersion)
		if err != nil {
			return false, err
		}
		return constraints.Check(v), nil
	case "pypi":
		constraints, err := pep440.NewSpecifiers(expression)
		if err != nil {
			return false, err
		}
		v, err := pep440.Parse(queryVersion)
		if err != nil {
			return false, err
		}
		return constraints.Check(v), nil
	case "maven":
		constraints, err := mvn.NewConstraints(expression)
		if err != nil {
			return false, err
		}
		v, err := mvn.NewVersion(queryVersion)
		if err != nil {
			return false, err
		}
		return constraints.Check(v), nil
	case "go", "crates.io", "nuget", "julia", "swifturl", "pub", "hex":
		constraints, err := semver.NewConstraints(expression)
		if err != nil {
			return false, err
		}
		v, err := semver.Parse(queryVersion)
		if err != nil {
			return false, err
		}
		return constraints.Check(v), nil
	default:
		constraints, err := version.NewConstraints(expression)
		if err != nil {
			return false, err
		}
		v, err := version.Parse(queryVersion)
		if err != nil {
			return false, err
		}
		return constraints.Check(v), nil
	}
}
