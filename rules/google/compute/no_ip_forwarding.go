package compute

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckNoIpForwarding = rules.Register(
	rules.Rule{
		Provider:    provider.GoogleProvider,
		Service:     "compute",
		ShortCode:   "no-ip-forwarding",
		Summary:     "Instances should not have IP forwarding enabled",
		Impact:      "Instance can send/receive packets without the explicit instance address",
		Resolution:  "Disable IP forwarding",
		Explanation: `Disabling IP forwarding ensuresthe instance can only receive packets addressed to the instance and can only send packets with a source address of the instance.`,
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
