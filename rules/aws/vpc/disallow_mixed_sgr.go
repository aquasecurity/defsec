package vpc

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckDisallowMixedSgr = rules.Register(
	rules.Rule{
		Provider:    provider.AWSProvider,
		Service:     "vpc",
		ShortCode:   "disallow-mixed-sgr",
		Summary:     "Ensures that usage of security groups with inline rules and security group rule resources are not mixed.",
		Impact:      "Security group rules will be overwritten and will result in unintended blocking of network traffic",
		Resolution:  "Either define all of a security group's rules inline, or none of the security group's rules inline",
		Explanation: `Mixing Terraform standalone security_group_rule resource and security_group resource with inline ingress/egress rules results in rules being overwritten during Terraform apply.`,
		Links: []string{ 
		},
		Severity: severity.Low,
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
