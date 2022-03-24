package ssm

import (
	"github.com/aquasecurity/defsec/parsers/terraform"
	"github.com/aquasecurity/defsec/providers"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
)

var AvoidSecretLeaksViaHTTP = rules.Register(
	rules.Rule{
		AVDID:       "AVD-AWS-0134",
		Provider:    providers.AWSProvider,
		Service:     "ssm",
		ShortCode:   "avoid-secret-leaks-via-http",
		Summary:     "Secrets should not be leaked via HTTP data blocks",
		Impact:      "",
		Resolution:  "",
		Explanation: ``,
		Links: []string{
			"",
		},
		Terraform: &rules.EngineMetadata{
			GoodExamples:        nil,
			BadExamples:         nil,
			Links:               nil,
			RemediationMarkdown: ``,
		},
		CustomChecks: rules.CustomChecks{
			Terraform: &rules.TerraformCustomCheck{
				RequiredTypes:  []string{"data"},
				RequiredLabels: []string{"http"},
				Check: func(block *terraform.Block, module *terraform.Module) (results rules.Results) {

					return
				},
			},
		},
		Severity: severity.Critical,
	},
	nil,
)
