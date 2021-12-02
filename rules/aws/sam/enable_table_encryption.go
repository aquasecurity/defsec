package sam

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckTableEncryptionEnabled = rules.Register(
	rules.Rule{
		AVDID:       "AVD-AWS-0121",
		Provider:    provider.AWSProvider,
		Service:     "sam",
		ShortCode:   "enable-table-encryption",
		Summary:     "SAM Simple table must have server side encryption enabled.",
		Impact:      "Data stored in the table that is unencrypted may be vulnerable to compromise",
		Resolution:  "Enable server side encryption",
		Explanation: `Encryption should be enabled at all available levels to ensure that data is protected if compromised.`,
		Links: []string{
			"https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/sam-resource-simpletable.html#sam-simpletable-ssespecification",
		},
		Severity: severity.High,
	},
	func(s *state.State) (results rules.Results) {
		for _, api := range s.AWS.SAM.APIs {
			if api.DomainConfiguration.SecurityPolicy.NotEqualTo("TLS_1_2") {
				results.Add(
					"Domain name is configured with an outdated TLS policy.",
					&api,
					api.DomainConfiguration.SecurityPolicy,
				)
			} else {
				results.AddPassed(&api)
			}
		}
		return
	},
)
