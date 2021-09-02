package mq

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckNoPublicAccess = rules.Register(
	rules.Rule{
		Provider:    provider.AWSProvider,
		Service:     "mq",
		ShortCode:   "no-public-access",
		Summary:     "Ensure MQ Broker is not publicly exposed",
		Impact:      "Publicly accessible MQ Broker may be vulnerable to compromise",
		Resolution:  "Disable public access when not required",
		Explanation: `Public access of the MQ broker should be disabled and only allow routes to applications that require access.`,
		Links: []string{ 
		},
		Severity: severity.High,
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
