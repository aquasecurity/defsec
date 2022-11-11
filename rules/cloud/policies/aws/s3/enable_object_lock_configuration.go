package s3

import (
	"github.com/aquasecurity/defsec/internal/rules"
	"github.com/aquasecurity/defsec/pkg/providers"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/severity"
	"github.com/aquasecurity/defsec/pkg/state"
)

var CheckObjectLockConfigured = rules.Register(
	scan.Rule{
		AVDID:       "AVD-AWS-0181",
		Provider:    providers.AWSProvider,
		Service:     "s3",
		ShortCode:   "enable-object-lock-configuration",
		Summary:     "S3 Bucket does not have object lock configuration enabled.",
		Impact:      "The bucket object can be deleted or modified",
		Resolution:  "Configure bucket object lock",
		Explanation: `S3 Bucket objects lock should be configured.`,
		Links: []string{
			"https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html",
		},

		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformEnableObjectLockConfigurationGoodExamples,
			BadExamples:         terraformEnableObjectLockConfigurationBadExamples,
			Links:               terraformEnableObjectLockConfigurationLinks,
			RemediationMarkdown: terraformEnableObjectLockConfigurationRemediationMarkdown,
		},
		CloudFormation: &scan.EngineMetadata{
			GoodExamples:        cloudFormationEnableObjectLockConfigurationGoodExamples,
			BadExamples:         cloudFormationEnableObjectLockConfigurationBadExamples,
			Links:               cloudFormationEnableObjectLockConfigurationLinks,
			RemediationMarkdown: cloudFormationEnableObjectLockConfigurationRemediationMarkdown,
		},
		Severity: severity.Medium,
	},
	func(s *state.State) (results scan.Results) {
		for _, bucket := range s.AWS.S3.Buckets {
			if bucket.ObjectLockConfiguration.Enabled.IsFalse() {
				results.Add(
					"Object lock not configured on bucket",
					bucket.ObjectLockConfiguration.Enabled,
				)
			} else {
				results.AddPassed(&bucket, "Object lock correctly configured on bucket")
			}
		}
		return results
	},
)
