package cloudtrail

import (
	"github.com/aquasecurity/defsec/internal/rules"
	"github.com/aquasecurity/defsec/pkg/framework"
	"github.com/aquasecurity/defsec/pkg/providers"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/severity"
	"github.com/aquasecurity/defsec/pkg/state"
)

var checkEnsureCloudwatchIntegration = rules.Register(
	scan.Rule{
		AVDID:     "AVD-AWS-0162",
		Provider:  providers.AWSProvider,
		Service:   "cloudtrail",
		ShortCode: "ensure-cloudwatch-integration",
		Frameworks: map[framework.Framework][]string{
			framework.Default:     nil,
			framework.CIS_AWS_1_2: {"2.4"},
			framework.CIS_AWS_1_4: {"3.4"},
		},
		Summary:    "CloudTrail logs should be stored in S3 and also sent to CloudWatch Logs",
		Impact:     "Realtime log analysis is not available without enabling CloudWatch logging",
		Resolution: "Enable logging to CloudWatch",
		Explanation: `
CloudTrail is a web service that records AWS API calls made in a given account. The recorded information includes the identity of the API caller, the time of the API call, the source IP address of the API caller, the request parameters, and the response elements returned by the AWS service.

CloudTrail uses Amazon S3 for log file storage and delivery, so log files are stored durably. In addition to capturing CloudTrail logs in a specified Amazon S3 bucket for long-term analysis, you can perform real-time analysis by configuring CloudTrail to send logs to CloudWatch Logs.

For a trail that is enabled in all Regions in an account, CloudTrail sends log files from all those Regions to a CloudWatch Logs log group.
`,
		Links: []string{
			"https://docs.aws.amazon.com/awscloudtrail/latest/userguide/send-cloudtrail-events-to-cloudwatch-logs.html#send-cloudtrail-events-to-cloudwatch-logs-console",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformEnsureCloudwatchIntegrationGoodExamples,
			BadExamples:         terraformEnsureCloudwatchIntegrationBadExamples,
			Links:               terraformEnsureCloudwatchIntegrationLinks,
			RemediationMarkdown: terraformEnsureCloudwatchIntegrationRemediationMarkdown,
		},
		CloudFormation: &scan.EngineMetadata{
			GoodExamples:        cloudFormationEnsureCloudwatchIntegrationGoodExamples,
			BadExamples:         cloudFormationEnsureCloudwatchIntegrationBadExamples,
			Links:               cloudFormationEnsureCloudwatchIntegrationLinks,
			RemediationMarkdown: cloudFormationEnsureCloudwatchIntegrationRemediationMarkdown,
		},
		Severity: severity.Low,
	},
	func(s *state.State) (results scan.Results) {
		for _, trail := range s.AWS.CloudTrail.Trails {
			if trail.CloudWatchLogsLogGroupArn.IsEmpty() {
				results.Add("Trail does not have CloudWatch logging configured", &trail)
			} else {
				results.AddPassed(&trail)
			}
		}
		return
	},
)
