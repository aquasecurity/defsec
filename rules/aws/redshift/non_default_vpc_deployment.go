package redshift

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckNonDefaultVpcDeployment = rules.Register(
	rules.Rule{
		Provider:    provider.AWSProvider,
		Service:     "redshift",
		ShortCode:   "non-default-vpc-deployment",
		Summary:     "Redshift cluster should be deployed into a specific VPC",
		Impact:      "Redshift cluster does not benefit from VPC security if it is deployed in EC2 classic mode",
		Resolution:  "Deploy Redshift cluster into a non default VPC",
		Explanation: `Redshift clusters that are created without subnet details will be created in EC2 classic mode, meaning that they will be outside of a known VPC and running in tennant.

In order to benefit from the additional security features achieved with using an owned VPC, the subnet should be set.`,
		Links: []string{ 
			"https://docs.aws.amazon.com/redshift/latest/mgmt/managing-clusters-vpc.html",
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
