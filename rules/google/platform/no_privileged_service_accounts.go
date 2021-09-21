package iam

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckNoPrivilegedServiceAccounts = rules.Register(
	rules.Rule{
		Provider:    provider.GoogleProvider,
		Service:     "platform",
		ShortCode:   "no-privileged-service-accounts",
		Summary:     "Service accounts should not have roles assigned with excessive privileges",
		Impact:      "Cloud account takeover if a resource using a service account is compromised",
		Resolution:  "Limit service account access to minimal required set",
		Explanation: `Service accounts should have a minimal set of permissions assigned in order to do their job. They should never have excessive access as if compromised, an attacker can escalate privileges and take over the entire account.`,
		Links: []string{
			"https://cloud.google.com/iam/docs/understanding-roles",
		},
		Severity: severity.High,
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
