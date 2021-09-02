package vpc

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckNoPublicIngressSgr = rules.Register(
	rules.Rule{
		Provider:    provider.AWSProvider,
		Service:     "vpc",
		ShortCode:   "no-public-ingress-sgr",
		Summary:     "An ingress security group rule allows traffic from /0.",
		Impact:      "Your port exposed to the internet",
		Resolution:  "Set a more restrictive cidr range",
		Explanation: `Opening up ports to the public internet is generally to be avoided. You should restrict access to IP addresses or ranges that explicitly require it where possible.`,
		Links: []string{ 
			"https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/security-group-rules-reference.html",
		},
		Severity: severity.Critical,
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
