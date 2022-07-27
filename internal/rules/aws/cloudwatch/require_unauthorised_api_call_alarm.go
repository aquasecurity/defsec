package cloudwatch

import (
	"github.com/aquasecurity/defsec/internal/rules"
	"github.com/aquasecurity/defsec/internal/types"
	"github.com/aquasecurity/defsec/pkg/framework"
	"github.com/aquasecurity/defsec/pkg/providers"
	"github.com/aquasecurity/defsec/pkg/providers/aws/cloudwatch"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/severity"
	"github.com/aquasecurity/defsec/pkg/state"
)

var requireUnauthorizedApiCallAlarm = rules.Register(
	scan.Rule{
		AVDID:      "AVD-AWS-0146",
		Provider:   providers.AWSProvider,
		Service:    "cloudwatch",
		ShortCode:  "require-unauthorised-api-call-alarm",
		Summary:    "Ensure a log metric filter and alarm exist for unauthorized API calls",
		Impact:     "",
		Resolution: "",
		Frameworks: map[framework.Framework][]string{
			framework.Default: nil,
			framework.CIS_AWS_1_2: {
				"4.1",
			},
		},
		Explanation: `You can do real-time monitoring of API calls by directing CloudTrail logs to CloudWatch Logs and establishing corresponding metric filters and alarms. You can have more than one VPC in an account, and you can create a peer connection between two VPCs, enabling network traffic to route between VPCs.

CIS recommends that you create a metric filter and alarm for changes to VPCs. Monitoring these changes helps ensure that authentication and authorization controls remain intact.`,
		Links: []string{
			"https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/encrypt-log-data-kms.html",
		},
		Terraform:      &scan.EngineMetadata{},
		CloudFormation: &scan.EngineMetadata{},
		Severity:       severity.Low,
	},
	func(s *state.State) (results scan.Results) {

		multiRegionTrails := s.AWS.CloudTrail.MultiRegionTrails()
		for _, trail := range multiRegionTrails {
			logGroup := s.AWS.CloudWatch.GetLogGroupByArn(trail.CloudWatchLogsLogGroupArn.Value())
			if logGroup == nil || trail.IsLogging.IsFalse() {
				continue
			}

			var metricFilter *cloudwatch.MetricFilter
			for _, filter := range logGroup.MetricFilters {
				if filter.FilterPattern.Contains(`($.errorCode = "*UnauthorizedOperation") || ($.errorCode = "AccessDenied*")`, types.IgnoreWhitespace) {
					metricFilter = &filter
					break
				}
			}

			if metricFilter == nil {
				results.Add("Cloudtrail has no unauthorized API log filter", trail)
				continue
			}

			s.AWS.CloudWatch.GetAlarmByName(metricFilter.)

		}

		return
	},
)
