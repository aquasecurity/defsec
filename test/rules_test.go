package test

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/defsec/internal/rules"

	"github.com/aquasecurity/defsec/test/testutil"
)

func TestAVDIDs(t *testing.T) {
	existing := make(map[string]struct{})
	for _, rule := range rules.GetRegistered() {
		t.Run(rule.Rule().LongID(), func(t *testing.T) {
			if rule.Rule().AVDID == "" {
				t.Errorf("Rule has no AVD ID: %#v", rule)
				return
			}
			if _, ok := existing[rule.Rule().AVDID]; ok {
				t.Errorf("Rule detected with duplicate AVD ID: %s", rule.Rule().AVDID)
			}
		})
		existing[rule.Rule().AVDID] = struct{}{}
	}
}

func TestRulesAgainstExampleCode(t *testing.T) {
	for _, rule := range rules.GetRegistered() {
		testName := fmt.Sprintf("%s/%s", rule.Rule().AVDID, rule.Rule().LongID())
		t.Run(testName, func(t *testing.T) {
			rule := rule
			t.Parallel()

			t.Run("avd docs", func(t *testing.T) {
				provider := strings.ToLower(rule.Rule().Provider.ConstName())
				service := strings.ToLower(strings.ReplaceAll(rule.Rule().Service, "-", ""))
				_, err := os.Stat(filepath.Join("..", "avd_docs", provider, service, rule.Rule().AVDID, "docs.md"))
				require.NoError(t, err)
			})

			if rule.Rule().Terraform != nil {
				t.Run("terraform: good examples", func(t *testing.T) {
					for i, example := range rule.Rule().Terraform.GoodExamples {
						t.Run(fmt.Sprintf("example %d", i), func(t *testing.T) {
							results := scanHCL(t, example)
							testutil.AssertRuleNotFound(t, rule.Rule().LongID(), results, "Rule %s was detected in good example #%d:\n%s", rule.Rule().LongID(), i, example)
						})
					}
				})
				t.Run("terraform: bad examples", func(t *testing.T) {
					for i, example := range rule.Rule().Terraform.BadExamples {
						t.Run(fmt.Sprintf("example %d", i), func(t *testing.T) {
							results := scanHCL(t, example)
							testutil.AssertRuleFound(t, rule.Rule().LongID(), results, "Rule %s was not detected in bad example #%d:\n%s", rule.Rule().LongID(), i, example)

						})
					}
				})
			}
			if rule.Rule().CloudFormation != nil {
				t.Run("cloudformation: good examples", func(t *testing.T) {
					for i, example := range rule.Rule().CloudFormation.GoodExamples {
						t.Run(fmt.Sprintf("example %d", i), func(t *testing.T) {
							results := scanCF(t, example)
							testutil.AssertRuleNotFound(t, rule.Rule().LongID(), results, "Rule %s was detected in good example #%d:\n%s", rule.Rule().LongID(), i, example)
						})
					}
				})
				t.Run("cloudformation: bad examples", func(t *testing.T) {
					for i, example := range rule.Rule().CloudFormation.BadExamples {
						t.Run(fmt.Sprintf("example %d", i), func(t *testing.T) {
							results := scanCF(t, example)
							testutil.AssertRuleFound(t, rule.Rule().LongID(), results, "Rule %s was not detected in bad example #%d:\n%s", rule.Rule().LongID(), i, example)

						})
					}
				})
			}
		})
	}
}
