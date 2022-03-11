package test

import (
	"testing"

	"github.com/aquasecurity/defsec/parsers/terraform"
	"github.com/aquasecurity/defsec/providers"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/test/testutil"
)

func TestScanningJSON(t *testing.T) {

	var tests = []struct {
		name       string
		source     string
		shouldFail bool
	}{
		{
			name: "check results are picked up in tf json configs",
			source: `
			{
				"provider": {
					"aws": {
						"profile": null,
						"region": "eu-west-1"
					}
				},
				"resource": {
					"bad": {
						"thing": {
							"type": "ingress",
							"cidr_blocks": ["0.0.0.0/0"],
							"description": "testing"
						}
					}
				}
			}`,
			shouldFail: true,
		},
		{
			name: "check attributes are checked in tf json configs",
			source: `
			{
				"provider": {
					"aws": {
						"profile": null,
						"region": "eu-west-1"
					}
				},
				"resource": {
					"bad": {
						"or_not": {
							"secure": true
						}
					}
				}
			}`,
			shouldFail: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			r1 := rules.Rule{
				Provider:  providers.AWSProvider,
				Service:   "service",
				ShortCode: "abc123",
				Severity:  severity.High,
				CustomChecks: rules.CustomChecks{
					Terraform: &rules.TerraformCustomCheck{
						RequiredLabels: []string{"bad"},
						Check: func(resourceBlock *terraform.Block, _ *terraform.Module) (results rules.Results) {
							if resourceBlock.GetAttribute("secure").IsTrue() {
								return
							}
							results.Add("something", resourceBlock)
							return
						},
					},
				},
			}
			reg := rules.Register(r1, nil)
			defer rules.Deregister(reg)

			results := testutil.ScanJSON(test.source, t)
			var include, exclude string
			if test.shouldFail {
				include = r1.LongID()
			} else {
				exclude = r1.LongID()
			}
			if include != "" {
				testutil.AssertRuleFound(t, include, results, "false negative found")
			}
			if exclude != "" {
				testutil.AssertRuleNotFound(t, exclude, results, "false positive found")
			}
		})
	}
}
