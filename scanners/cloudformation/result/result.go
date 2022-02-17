package result

import (
	"github.com/aquasecurity/defsec/parsers/types"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
)

type Status string

const (
	Failed  Status = "failed"
	Passed  Status = "passed"
	Ignored Status = "ignored"
)

// Result is a positive result for a security check. It encapsulates a code unique to the specific check it was raised
// by, a human-readable description and a range
type Result struct {
	AVDID           string            `json:"avd_id"`
	RuleID          string            `json:"rule_id"`
	RuleSummary     string            `json:"rule_description"`
	Impact          string            `json:"impact"`
	Resolution      string            `json:"resolution"`
	Links           []string          `json:"links"`
	Description     string            `json:"description"`
	RangeAnnotation string            `json:"-"`
	Severity        severity.Severity `json:"severity"`
	Status          rules.Status      `json:"status"`
	ResourceRange   types.Range       `json:"location"`
	PropertyRange   types.Range       `json:"-"`
	Resource        string            `json:"resource"`
}
