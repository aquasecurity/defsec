package eks

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckEncryptSecrets = rules.Register(
	rules.Rule{
		Provider:    provider.AWSProvider,
		Service:     "eks",
		ShortCode:   "encrypt-secrets",
		Summary:     "EKS should have the encryption of secrets enabled",
		Impact:      "EKS secrets could be read if compromised",
		Resolution:  "Enable encryption of EKS secrets",
		Explanation: `EKS cluster resources should have the encryption_config block set with protection of the secrets resource.`,
		Links: []string{ 
			"https://aws.amazon.com/about-aws/whats-new/2020/03/amazon-eks-adds-envelope-encryption-for-secrets-with-aws-kms/",
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
