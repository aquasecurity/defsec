package authorization

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckLimitRoleActions = rules.Register(
	rules.Rule{
		Provider:    provider.AzureProvider,
		Service:     "authorization",
		ShortCode:   "limit-role-actions",
		Summary:     "Roles limited to the required actions",
		Impact:      "Open permissions for subscriptions could result in an easily compromisable account",
		Resolution:  "Use targeted permissions for roles",
		Explanation: `The permissions granted to a role should be kept to the minimum required to be able to do the task. Wildcard permissions must not be used.`,
		Links: []string{ 
		},
		Severity: severity.Medium,
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
