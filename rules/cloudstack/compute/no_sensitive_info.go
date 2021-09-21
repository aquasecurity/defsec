package compute

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckNoSensitiveInfo = rules.Register(
	rules.Rule{
		Provider:    provider.CloudStackProvider,
		Service:     "compute",
		ShortCode:   "no-sensitive-info",
		Summary:     "No sensitive data stored in user_data",
		Impact:      "Sensitive credentials in the user data can be leaked",
		Resolution:  "Don't use sensitive data in the user data section",
		Explanation: `When creating instances, user data can be used during the initial configuration. User data must not contain sensitive information`,
		Links:       []string{},
		Severity:    severity.High,
	},
	func(s *state.State) (results rules.Results) {
		for _, x := range s.AWS.S3.Buckets {
			if x.Encryption.Enabled.IsFalse() {
				results.Add(
					"",
					x.Encryption.Enabled,
					
				)
			}
		}
		return
	},
)
