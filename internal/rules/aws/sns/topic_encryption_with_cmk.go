package sns

import (
	"github.com/aquasecurity/defsec/internal/rules"
	"github.com/aquasecurity/defsec/pkg/providers"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/severity"
	"github.com/aquasecurity/defsec/pkg/state"
)

var CheckTopicEncryptionUsesCMK = rules.Register(
	scan.Rule{
		AVDID:       "AVD-AWS-0136",
		ShortCode:   "topic-encryption-use-cmk",
		Summary:     "SNS topic not encrypted with CMK.",
		Explanation: `Topics should be encrypted with customer managed KMS keys and not default AWS managed keys, in order to allow granular key management.`,
		Impact:      "Key management very limited when using default keys.",
		Resolution:  "Use a CMK for SNS Topic encryption",
		Provider:    providers.AWSProvider,
		Service:     "sns",
		Links: []string{
			"https://docs.aws.amazon.com/sns/latest/dg/sns-server-side-encryption.html",
		},
		Severity: severity.High,
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformTopicEncryptionUsesCMKGoodExamples,
			BadExamples:         terraformTopicEncryptionUsesCMKBadExamples,
			Links:               terraformTopicEncryptionUsesCMKLinks,
			RemediationMarkdown: terraformTopicEncryptionUsesCMKRemediationMarkdown,
		},
		CloudFormation: &scan.EngineMetadata{
			GoodExamples:        cloudFormationTopicEncryptionUsesCMKGoodExamples,
			BadExamples:         cloudFormationTopicEncryptionUsesCMKBadExamples,
			Links:               cloudFormationTopicEncryptionUsesCMKLinks,
			RemediationMarkdown: cloudFormationTopicEncryptionUsesCMKRemediationMarkdown,
		},
		CustomChecks: scan.CustomChecks{},
		RegoPackage:  "",
	},
	func(s *state.State) (results scan.Results) {
		for _, topic := range s.AWS.SNS.Topics {
			if topic.Encryption.KMSKeyID.EqualTo("alias/aws/sns") {
				results.Add(
					"Topic encryption does not use a customer managed key.",
					topic.Encryption.KMSKeyID,
				)
			} else {
				results.AddPassed(&topic)
			}
		}
		return
	},
)
