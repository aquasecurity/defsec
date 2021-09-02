package iam

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckBlockKmsPolicyWildcard = rules.Register(
	rules.Rule{
		Provider:    provider.AWSProvider,
		Service:     "iam",
		ShortCode:   "block-kms-policy-wildcard",
		Summary:     "IAM customer managed policies should not allow decryption actions on all KMS keys",
		Impact:      "Identities may be able to decrypt data which they should not have access to",
		Resolution:  "Scope down the resources of the IAM policy to specific keys",
		Explanation: `IAM policies define which actions an identity (user, group, or role) can perform on which resources. Following security best practices, AWS recommends that you allow least privilege. In other words, you should grant to identities only the kms:Decrypt or kms:ReEncryptFrom permissions and only for the keys that are required to perform a task.`,
		Links: []string{ 
			"https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-standards-fsbp-controls.html#fsbp-kms-1",
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
