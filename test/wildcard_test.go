package test

import (
	"fmt"
	"testing"

	"github.com/aquasecurity/defsec/test/testutil"

	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"

	"github.com/aquasecurity/defsec/parsers/terraform"
)

func Test_WildcardMatchingOnRequiredLabels(t *testing.T) {

	tests := []struct {
		input           string
		pattern         string
		expectedFailure bool
	}{
		{
			pattern:         "aws_*",
			input:           `resource "aws_instance" "blah" {}`,
			expectedFailure: true,
		},
		{
			pattern:         "gcp_*",
			input:           `resource "aws_instance" "blah" {}`,
			expectedFailure: false,
		},
		{
			pattern:         "x_aws_*",
			input:           `resource "aws_instance" "blah" {}`,
			expectedFailure: false,
		},
		{
			pattern:         "aws_security_group*",
			input:           `resource "aws_security_group" "blah" {}`,
			expectedFailure: true,
		},
		{
			pattern:         "aws_security_group*",
			input:           `resource "aws_security_group_rule" "blah" {}`,
			expectedFailure: true,
		},
	}

	for i, test := range tests {

		code := fmt.Sprintf("wild%d", i)

		t.Run(code, func(t *testing.T) {

			rule := rules.Rule{
				Service:   "service",
				ShortCode: code,
				Summary:   "blah",
				Provider:  "custom",
				Severity:  severity.High,
				CustomChecks: rules.CustomChecks{
					Terraform: &rules.TerraformCustomCheck{
						RequiredTypes:  []string{"resource"},
						RequiredLabels: []string{test.pattern},
						Check: func(resourceBlock *terraform.Block, _ *terraform.Module) (results rules.Results) {
							results.Add("Custom check failed for resource.", resourceBlock)
							return
						},
					},
				},
			}
			reg := rules.Register(rule, nil)
			defer rules.Deregister(reg)

			results := scanHCL(t, test.input)

			if test.expectedFailure {
				testutil.AssertRuleFound(t, fmt.Sprintf("custom-service-%s", code), results, "")
			} else {
				testutil.AssertRuleNotFound(t, fmt.Sprintf("custom-service-%s", code), results, "")
			}
		})
	}

}
