package appservice

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckAccountIdentityRegistered = rules.Register(
	rules.Rule{
		Provider:    provider.AzureProvider,
		Service:     "appservice",
		ShortCode:   "account-identity-registered",
		Summary:     "Web App has registration with AD enabled",
		Impact:      "Interaction between services can't easily be achieved without username/password",
		Resolution:  "Register the app identity with AD",
		Explanation: `Registering the identity used by an App with AD allows it to interact with other services without using username and password`,
		Links: []string{ 
		},
		Severity: severity.Low,
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
