package fw

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckNoPublicAccess = rules.Register(
	rules.Rule{
		Provider:    provider.OpenStackProvider,
		Service:     "fw",
		ShortCode:   "no-public-access",
		Summary:     "A firewall rule allows traffic from/to the public internet",
		Impact:      "Exposure of infrastructure to the public internet",
		Resolution:  "Employ more restrictive firewall rules",
		Explanation: `Opening up ports to the public internet is generally to be avoided. You should restrict access to IP addresses or ranges that explicitly require it where possible.`,
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
