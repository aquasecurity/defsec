package launch

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckNoSensitiveInfo = rules.Register(
	rules.Rule{
		Provider:    provider.AWSProvider,
		Service:     "launch",
		ShortCode:   "no-sensitive-info",
		Summary:     "Ensure all data stored in the Launch configuration EBS is securely encrypted",
		Impact:      "Sensitive credentials in user data can be leaked",
		Resolution:  "Don't use sensitive data in user data",
		Explanation: `When creating Launch Configurations, user data can be used for the initial configuration of the instance. User data must not contain any sensitive data.`,
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
