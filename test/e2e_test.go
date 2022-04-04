package test

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/aquasecurity/defsec/adapters/terraform"

	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/defsec/adapters/cloudformation"
	cfParser "github.com/aquasecurity/defsec/parsers/cloudformation/parser"
	tfParser "github.com/aquasecurity/defsec/parsers/terraform/parser"

	"github.com/stretchr/testify/assert"

	_ "github.com/aquasecurity/defsec/loader"
	"github.com/aquasecurity/defsec/rules"
)

func Test_AllRules(t *testing.T) {
	for _, rule := range rules.GetRegistered() {
		if !rule.HasLogic() {
			continue
		}
		t.Run(rule.Rule().LongID(), func(t *testing.T) {
			if rule.Rule().Terraform != nil {
				t.Run("terraform: good examples", func(t *testing.T) {
					for i, example := range rule.Rule().Terraform.GoodExamples {
						t.Run(fmt.Sprintf("example %d", i), func(t *testing.T) {
							results, err := runRuleAgainstTerraform(rule, example)
							require.NoError(t, err)
							assertRuleNotFound(t, rule.Rule().LongID(), results, "Rule %s was detected in good example #%d:\n%s", rule.Rule().LongID(), i, example)
						})
					}
				})
				t.Run("terraform: bad examples", func(t *testing.T) {
					for i, example := range rule.Rule().Terraform.BadExamples {
						t.Run(fmt.Sprintf("example %d", i), func(t *testing.T) {
							results, err := runRuleAgainstTerraform(rule, example)
							require.NoError(t, err)
							assertRuleFound(t, rule.Rule().LongID(), results, "Rule %s was not detected in bad example #%d:\n%s", rule.Rule().LongID(), i, example)
						})
					}
				})
			}
			if rule.Rule().CloudFormation != nil {
				t.Run("cloudformation: good examples", func(t *testing.T) {
					t.Skip()
					for i, example := range rule.Rule().CloudFormation.GoodExamples {
						t.Run(fmt.Sprintf("example %d", i), func(t *testing.T) {
							results, err := runRuleAgainstCloudFormation(rule, example)
							require.NoError(t, err)
							assertRuleNotFound(t, rule.Rule().LongID(), results, "Rule %s was detected in good example #%d:\n%s", rule.Rule().LongID(), i, example)
						})
					}
				})
				t.Run("cloudformation: bad examples", func(t *testing.T) {
					t.Skip()
					for i, example := range rule.Rule().CloudFormation.BadExamples {
						t.Run(fmt.Sprintf("example %d", i), func(t *testing.T) {
							results, err := runRuleAgainstCloudFormation(rule, example)
							require.NoError(t, err)
							assertRuleFound(t, rule.Rule().LongID(), results, "Rule %s was not detected in bad example #%d:\n%s", rule.Rule().LongID(), i, example)
						})
					}
				})
			}
		})
	}
}

func runRuleAgainstTerraform(rule rules.RegisteredRule, src string) ([]rules.Result, error) {
	p := tfParser.New()
	if err := p.ParseContent([]byte(src), "main.tf"); err != nil {
		return nil, err
	}
	modules, _, err := p.EvaluateAll()
	if err != nil {
		return nil, err
	}
	state := terraform.Adapt(modules)
	return rule.Evaluate(state), nil
}

func runRuleAgainstCloudFormation(rule rules.RegisteredRule, src string) ([]rules.Result, error) {
	p := cfParser.New()
	ctx, err := p.Parse(bytes.NewReader([]byte(src)), "main.yaml")
	if err != nil {
		return nil, err
	}
	state := cloudformation.Adapt(*ctx)
	return rule.Evaluate(state), nil
}

func assertRuleFound(t *testing.T, ruleID string, results []rules.Result, message string, args ...interface{}) {
	found := ruleIDInResults(ruleID, results)
	assert.True(t, found, append([]interface{}{message}, args...)...)
	for _, result := range results {
		if result.Rule().LongID() == ruleID {
			m := result.Metadata()
			meta := &m
			for meta != nil {
				assert.NotNil(t, meta.Range(), 0)
				assert.Greater(t, meta.Range().GetStartLine(), 0)
				assert.Greater(t, meta.Range().GetEndLine(), 0)
				meta = meta.Parent()
			}
		}
	}
}

func assertRuleNotFound(t *testing.T, ruleID string, results []rules.Result, message string, args ...interface{}) {
	found := ruleIDInResults(ruleID, results)
	assert.False(t, found, append([]interface{}{message}, args...)...)
}

func ruleIDInResults(ruleID string, results []rules.Result) bool {
	for _, res := range results {
		if res.Status() == rules.StatusPassed {
			continue
		}
		if res.Rule().LongID() == ruleID {
			return true
		}
	}
	return false
}
