package parser

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/aquasecurity/defsec/pkg/scan"
)

type Ignore struct {
	RuleID string
	Expiry *time.Time
}

func IsIgnored(scanResult scan.Result, ignores []Ignore) bool {
	for _, ignore := range ignores {
		if ignore.RuleID == scanResult.Rule().AVDID || ignore.RuleID == scanResult.Rule().LongID() || ignore.RuleID == "*" {
			if ignore.Expiry == nil || time.Now().Before(*ignore.Expiry) {
				return true
			}
		}
	}
	return false
}

func parseIgnores(lines []string) []Ignore {
	var ignores []Ignore
	for _, line := range lines {
		line = strings.TrimSpace(line)
		lineIgnores := parseIgnoresFromLine(line)
		ignores = append(ignores, lineIgnores...)
	}

	return ignores

}

var commentPattern = regexp.MustCompile(`^\s*([/]+|/\*|#)+\s*trivy:`)

func parseIgnoresFromLine(input string) []Ignore {
	var ignores []Ignore
	input = commentPattern.ReplaceAllString(input, "trivy:")
	bits := strings.Split(strings.TrimSpace(input), " ")
	for _, bit := range bits {
		bit := strings.TrimSpace(bit)
		bit = strings.TrimPrefix(bit, "#")
		bit = strings.TrimPrefix(bit, "//")
		bit = strings.TrimPrefix(bit, "/*")

		if strings.HasPrefix(bit, "trivy:") {
			ignore, err := parseIgnoreFromComment(bit)
			if err != nil {
				continue
			}
			ignores = append(ignores, *ignore)
		}
	}
	return ignores
}

func parseIgnoreFromComment(input string) (*Ignore, error) {
	var ignore Ignore
	if !strings.HasPrefix(input, "trivy:") {
		return nil, fmt.Errorf("invalid ignore")
	}

	input = input[6:]
	segments := strings.Split(input, ":")

	for i := 0; i < len(segments)-1; i += 2 {
		key := segments[i]
		val := segments[i+1]
		switch key {
		case "ignore":
			ignore.RuleID = val
		case "exp":
			parsed, err := time.Parse("2006-01-02", val)
			if err != nil {
				return &ignore, err
			}
			ignore.Expiry = &parsed
		}
	}
	return &ignore, nil
}
