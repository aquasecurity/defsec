package misc

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckNoExposingPlaintextCredentials = rules.Register(
	rules.Rule{
		Provider:    provider.AWSProvider,
		Service:     "misc",
		ShortCode:   "no-exposing-plaintext-credentials",
		Summary:     "AWS provider has access credentials specified.",
		Impact:      "Exposing the credentials in the Terraform provider increases the risk of secret leakage",
		Resolution:  "Don't include access credentials in plain text",
		Explanation: `The AWS provider block should not contain hardcoded credentials. These can be passed in securely as runtime using environment variables.`,
		Links: []string{ 
			"https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html",
		},
		Severity: severity.Critical,
	},
	func(s *state.State) (results rules.Results) {
		for _, x := range s.AWS.S3.Buckets {
			if x.Encryption.Enabled.IsFalse() {
				results.Add(
					"",
					x.Encryption.Enabled.Metadata(),
					x.Encryption.Enabled.Value(),
				)
			}
		}
		return
	},
)
