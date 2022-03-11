package test

import (
	"fmt"
	"testing"

	"github.com/aquasecurity/defsec/rules"

	"github.com/aquasecurity/defsec/test/testutil"
)

func TestDefSecUsage(t *testing.T) {
	for _, rule := range rules.GetRegistered() {
		t.Run(rule.Rule().LongID(), func(t *testing.T) {
			if rule.Rule().AVDID == "" {
				t.Errorf("Rule has no AVD ID: %#v", rule)
			}
		})
	}
}

func TestRulesAgainstExampleCode(t *testing.T) {
	for _, rule := range rules.GetRegistered() {
		if rule.Rule().Terraform == nil {
			continue
		}
		t.Run(rule.Rule().LongID(), func(t *testing.T) {
			t.Run("good examples", func(t *testing.T) {
				for i, example := range rule.Rule().Terraform.GoodExamples {
					t.Run(fmt.Sprintf("example %d", i), func(t *testing.T) {
						results := testutil.ScanHCL(example, t)
						testutil.AssertRuleNotFound(t, rule.Rule().LongID(), results, "Rule %s was detected in good example #%d:\n%s", rule.Rule().LongID(), i, example)
					})
				}
			})
			t.Run("bad examples", func(t *testing.T) {
				for i, example := range rule.Rule().Terraform.BadExamples {
					t.Run(fmt.Sprintf("example %d", i), func(t *testing.T) {
						results := testutil.ScanHCL(example, t)
						testutil.AssertRuleFound(t, rule.Rule().LongID(), results, "Rule %s was not detected in bad example #%d:\n%s", rule.Rule().LongID(), i, example)

					})
				}
			})

		})
	}
}
