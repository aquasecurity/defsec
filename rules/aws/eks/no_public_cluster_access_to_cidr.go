package eks

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckNoPublicClusterAccessToCidr = rules.Register(
	rules.Rule{
		Provider:    provider.AWSProvider,
		Service:     "eks",
		ShortCode:   "no-public-cluster-access-to-cidr",
		Summary:     "EKS cluster should not have open CIDR range for public access",
		Impact:      "EKS can be access from the internet",
		Resolution:  "Don't enable public access to EKS Clusters",
		Explanation: `EKS Clusters have public access cidrs set to 0.0.0.0/0 by default which is wide open to the internet. This should be explicitly set to a more specific CIDR range`,
		Links: []string{ 
			"https://docs.aws.amazon.com/eks/latest/userguide/create-public-private-vpc.html",
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
